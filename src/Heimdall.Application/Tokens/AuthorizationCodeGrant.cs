using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Heimdall.Application.Alerts;
using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.UserInfo;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Tokens;

/// <param name="ClientId">From the Basic header (confidential client) or the body (public client).</param>
/// <param name="ClientSecret">From the Basic header, or null for a public client.</param>
/// <param name="Code">The <c>code</c> parameter.</param>
/// <param name="CodeVerifier">The PKCE <c>code_verifier</c> (RFC 7636).</param>
/// <param name="RedirectUri">The <c>redirect_uri</c> parameter, or null.</param>
/// <param name="Resource">The <c>resource</c> parameter (RFC 8707), or null.</param>
/// <param name="DpopProof">The DPoP header, or null.</param>
public sealed record AuthorizationCodeRequest(
    string? ClientId,
    string? ClientSecret,
    string? Code,
    string? CodeVerifier,
    string? RedirectUri,
    string? Resource,
    string? DpopProof = null);

/// <summary>
/// The <c>authorization_code</c> grant at /token. The code is redeemed by one atomic conditional UPDATE that also checks
/// the client, the redirect URI, and the PKCE verifier. A second presentation of a redeemed code is reuse: Heimdall
/// revokes the family that the code started, writes an audit event, and raises an alert.
/// </summary>
public sealed class AuthorizationCodeGrant
{
    private const string GrantName = "authorization_code";

    private readonly ClientAuthenticator _authenticator;
    private readonly DpopTokenCheck _dpop;
    private readonly ITokenStore _tokens;
    private readonly ITokenSigner _signer;
    private readonly IAuditLog _audit;
    private readonly ISecurityAlerts _alerts;
    private readonly TimeProvider _time;

    public AuthorizationCodeGrant(
        ClientAuthenticator authenticator,
        DpopTokenCheck dpop,
        ITokenStore tokens,
        ITokenSigner signer,
        IAuditLog audit,
        ISecurityAlerts alerts,
        TimeProvider time)
    {
        _authenticator = authenticator;
        _dpop = dpop;
        _tokens = tokens;
        _signer = signer;
        _audit = audit;
        _alerts = alerts;
        _time = time;
    }

    public async Task<Result<TokenResponse>> HandleAsync(
        RequestContext context,
        AuthorizationCodeRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        var result = await IssueAsync(context, request, cancellationToken).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            await WriteAuditAsync(
                context,
                AuditEventTypes.TokenRejected,
                null,
                null,
                null,
                new Dictionary<string, string>
                {
                    ["grant_type"] = GrantName,
                    ["client_id"] = Truncate(request.ClientId, 128),
                    ["error"] = result.Error.Code,
                    ["reason"] = result.Error.AuditDetail,
                },
                cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    private async Task<Result<TokenResponse>> IssueAsync(
        RequestContext context,
        AuthorizationCodeRequest request,
        CancellationToken cancellationToken)
    {
        if (context.Tenant.Status != TenantStatus.Active)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidClient("tenant suspended"));
        }

        // Public clients send client_id only. Confidential clients authenticate with the Basic header (D10).
        var authentication = await _authenticator
            .AuthenticateAsync(context.Tenant.Id, request.ClientId, request.ClientSecret, cancellationToken)
            .ConfigureAwait(false);
        if (!authentication.IsSuccess)
        {
            return Result.Failure<TokenResponse>(authentication.Error);
        }

        var client = authentication.Value;
        if (!client.IsGrantAllowed(GrantType.AuthorizationCode))
        {
            return Result.Failure<TokenResponse>(OAuthError.UnauthorizedClient("authorization_code not allowed"));
        }

        if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.CodeVerifier))
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidRequest("code or code_verifier missing"));
        }

        if (!Pkce.IsValidVerifier(request.CodeVerifier))
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("code_verifier malformed"));
        }

        // The redirect URI must equal the stored one. When the client has one registered URI, it may leave it out.
        var redirectUri = request.RedirectUri ?? (client.RedirectUris.Count == 1 ? client.RedirectUris[0] : null);
        if (redirectUri is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidRequest("redirect_uri missing"));
        }

        var audience = client.ResolveUserAudience(request.Resource, UserInfoEndpoint.AudienceFor(context.Issuer));
        if (audience is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidTarget("resource missing or not allowed"));
        }

        // Last before the redemption: the replay check is a database write (D24 to D26).
        var dpop = await _dpop.CheckAsync(context, client, request.DpopProof, cancellationToken).ConfigureAwait(false);
        if (!dpop.IsSuccess)
        {
            return Result.Failure<TokenResponse>(dpop.Error);
        }

        var now = _time.GetUtcNow();
        var codeHash = TokenHash.Compute(request.Code);
        var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(request.CodeVerifier)));
        var familyId = Guid.CreateVersion7();

        AuthorizationCode? code;
        TokenResponse? response = null;
        TokenFamily? family = null;
        var transaction = await _tokens.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (transaction.ConfigureAwait(false))
        {
            code = await _tokens.RedeemCodeAsync(
                new CodeRedemption(context.Tenant.Id, codeHash, client.Id, redirectUri, challenge, familyId, now, dpop.Value),
                cancellationToken).ConfigureAwait(false);

            if (code is not null)
            {
                (response, family) = await CompleteRedemptionAsync(context, client, code, familyId, audience, dpop.Value, now, cancellationToken)
                    .ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        if (code is null)
        {
            // Outside the transaction: a reuse revokes a family and writes audit events, and a rollback must not undo
            // them. The failed redemption changed nothing, so there is nothing to roll back.
            return await ExplainFailureAsync(context, client, codeHash, redirectUri, challenge, dpop.Value, now, cancellationToken)
                .ConfigureAwait(false);
        }

        await WriteAuditAsync(
            context,
            AuditEventTypes.CodeRedeemed,
            client.Id,
            code.UserId,
            family!.Id,
            RedeemedData(code, audience, response!, dpop.Value),
            cancellationToken).ConfigureAwait(false);

        return Result.Success(response!);
    }

    /// <summary>
    /// Runs inside the redemption transaction: signs the tokens and inserts the family and the first refresh token.
    /// If no key can sign, it throws, the transaction rolls back, and the code stays usable.
    /// </summary>
    private async Task<(TokenResponse Response, TokenFamily Family)> CompleteRedemptionAsync(
        RequestContext context,
        Client client,
        AuthorizationCode code,
        Guid familyId,
        string audience,
        string? keyThumbprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var lifetimes = client.ResolveLifetimes(context.Tenant.Settings);

        // D24: a public client's family is bound to the DPoP key, so its refresh tokens need that key. A confidential
        // client authenticates at each refresh, so its family stays unbound.
        var familyKey = client.Type == ClientType.Public ? keyThumbprint : null;
        var family = TokenFamily.Start(familyId, context.Tenant.Id, client.Id, code.UserId, code.Id, code.Scope, lifetimes, now, familyKey);
        var response = await CreateTokensAsync(context, client, code, audience, lifetimes, keyThumbprint, now, cancellationToken).ConfigureAwait(false);

        _tokens.AddFamily(family);
        if (response.RefreshToken is { } refreshToken)
        {
            _tokens.AddRefreshToken(RefreshToken.Create(Guid.CreateVersion7(), context.Tenant.Id, family.Id, TokenHash.Compute(refreshToken), now));
        }

        await _tokens.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return (response, family);
    }

    private async Task<TokenResponse> CreateTokensAsync(
        RequestContext context,
        Client client,
        AuthorizationCode code,
        string audience,
        TokenLifetimes lifetimes,
        string? keyThumbprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var scopes = code.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var accessToken = await _signer.SignAccessTokenAsync(
            context.Tenant.Id,
            new AccessTokenClaims(
                context.Issuer,
                code.UserId.ToString(),
                audience,
                client.ClientId,
                scopes,
                now,
                now + lifetimes.AccessToken,
                Guid.NewGuid().ToString("N"),
                code.AuthTime,
                keyThumbprint),
            cancellationToken).ConfigureAwait(false);

        string? idToken = null;
        if (scopes.Contains("openid", StringComparer.Ordinal))
        {
            idToken = await _signer.SignIdTokenAsync(
                context.Tenant.Id,
                new IdTokenClaims(context.Issuer, code.UserId.ToString(), client.ClientId, now, now + lifetimes.AccessToken, code.AuthTime, code.Nonce),
                cancellationToken).ConfigureAwait(false);
        }

        // A refresh token only when the client may refresh and the user's grant includes offline_access.
        string? refreshToken = null;
        if (client.RefreshEnabled && scopes.Contains("offline_access", StringComparer.Ordinal))
        {
            refreshToken = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        }

        return new TokenResponse(
            accessToken,
            TokenResponse.TypeFor(keyThumbprint),
            (int)lifetimes.AccessToken.TotalSeconds,
            code.Scope,
            refreshToken,
            idToken);
    }

    /// <summary>
    /// The redemption matched no row. The caller always gets the same <c>invalid_grant</c> (D5). The audit log gets the
    /// reason. A code that was already redeemed is reuse: its family is revoked and an alert is raised.
    /// </summary>
    private async Task<Result<TokenResponse>> ExplainFailureAsync(
        RequestContext context,
        Client client,
        TokenHash codeHash,
        string redirectUri,
        string challenge,
        string? keyThumbprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var code = await _tokens.FindCodeAsync(context.Tenant.Id, codeHash, cancellationToken).ConfigureAwait(false);
        if (code is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("unknown code"));
        }

        if (code.RedeemedAt is not null)
        {
            await HandleReuseAsync(context, client, code, now, cancellationToken).ConfigureAwait(false);
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("code reused"));
        }

        if (now >= code.ExpiresAt)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("code expired"));
        }

        // D27: a code from a request with dpop_jkt needs a proof from that key. Like a refresh token of a bound family,
        // a missing proof is a client error, and a proof from another key means that the code belongs to someone else.
        if (code.ClientPk == client.Id
            && code.DpopKeyThumbprint is { } boundKey
            && !string.Equals(boundKey, keyThumbprint, StringComparison.Ordinal))
        {
            return Result.Failure<TokenResponse>(keyThumbprint is null
                ? OAuthError.InvalidDpopProof("proof required for a code bound by dpop_jkt")
                : OAuthError.InvalidGrant("DPoP key differs from dpop_jkt"));
        }

        // The last branch is a fallback. When every binding matches, the redemption above succeeds.
        // Stryker disable once Conditional,String : the fallback is unreachable, so no test can tell the two branches apart.
        var reason = code.ClientPk != client.Id
            ? "code issued to another client"
            : !string.Equals(code.RedirectUri, redirectUri, StringComparison.Ordinal)
                ? "redirect_uri mismatch"
                : !string.Equals(code.CodeChallenge, challenge, StringComparison.Ordinal)
                    ? "code_verifier mismatch"
                    : "code not redeemable";
        return Result.Failure<TokenResponse>(OAuthError.InvalidGrant(reason));
    }

    private async Task HandleReuseAsync(
        RequestContext context,
        Client client,
        AuthorizationCode code,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // Revoke the family derived from this code, not every session of the user (spec correction in CLAUDE.md).
        var revoked = code.FamilyId is { } familyId
            && await _tokens.RevokeFamilyAsync(context.Tenant.Id, familyId, FamilyRevocationReason.ReuseDetected, now, cancellationToken)
                .ConfigureAwait(false);

        var data = new Dictionary<string, string>
        {
            ["client_id"] = client.ClientId,
            ["code_id"] = code.Id.ToString(),
            ["family_revoked"] = revoked ? "yes" : "already revoked",
        };
        await WriteAuditAsync(context, AuditEventTypes.CodeReuseDetected, code.ClientPk, code.UserId, code.FamilyId, data, cancellationToken)
            .ConfigureAwait(false);
        if (revoked)
        {
            await WriteAuditAsync(
                context,
                AuditEventTypes.FamilyRevoked,
                code.ClientPk,
                code.UserId,
                code.FamilyId,
                new Dictionary<string, string> { ["reason"] = "reuse_detected" },
                cancellationToken).ConfigureAwait(false);
        }

        _alerts.Raise(AuditEventTypes.CodeReuseDetected, context.Tenant.Id, data);
    }

    private static Dictionary<string, string> RedeemedData(AuthorizationCode code, string audience, TokenResponse response, string? keyThumbprint)
    {
        var data = new Dictionary<string, string>
        {
            ["grant_type"] = GrantName,
            ["scope"] = code.Scope,
            ["aud"] = audience,
            ["refresh_issued"] = response.RefreshToken is null ? "no" : "yes",
        };
        if (keyThumbprint is not null)
        {
            data["dpop_jkt"] = keyThumbprint;
        }

        return data;
    }

    // Stryker disable once Equality : at that exact length, value[..maxLength] equals value.
    private static string Truncate(string? value, int maxLength) =>
        value is null ? string.Empty : value.Length <= maxLength ? value : value[..maxLength];

    private Task WriteAuditAsync(
        RequestContext context,
        string type,
        Guid? clientPk,
        Guid? userId,
        Guid? familyId,
        Dictionary<string, string> data,
        CancellationToken cancellationToken) =>
        _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                type,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: userId,
                clientPk: clientPk,
                familyId: familyId,
                data: data),
            cancellationToken);
}
