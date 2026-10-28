using System.Buffers.Text;
using System.Security.Cryptography;
using Heimdall.Application.Alerts;
using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.UserInfo;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;

namespace Heimdall.Application.Tokens;

/// <param name="ClientId">From the Basic header (confidential client) or the body (public client).</param>
/// <param name="ClientSecret">From the Basic header, or null for a public client.</param>
/// <param name="RefreshToken">The <c>refresh_token</c> parameter.</param>
/// <param name="Scope">The <c>scope</c> parameter, or null to keep the family's scope.</param>
/// <param name="Resource">The <c>resource</c> parameter (RFC 8707), or null.</param>
/// <param name="DpopProof">The DPoP header, or null.</param>
/// <param name="ClientAssertion">The <c>client_assertion</c> of a <c>private_key_jwt</c> client (D45), or null.</param>
public sealed record RefreshTokenRequest(
    string? ClientId,
    string? ClientSecret,
    string? RefreshToken,
    string? Scope,
    string? Resource,
    string? DpopProof = null,
    string? ClientAssertion = null);

/// <summary>
/// The <c>refresh_token</c> grant at /token, with rotation (threat model, "Refresh flow"). Each use returns a new refresh
/// token and marks the old one used, in one atomic conditional UPDATE. A second use of a used token is reuse: Heimdall
/// revokes the whole family at once, with no grace window, writes audit events, and raises an alert.
/// </summary>
/// <remarks>
/// No grace window is a recorded decision: a window reopens the race that reuse detection closes. A client must save the
/// new token before it uses it. The family's absolute lifetime never moves, so rotation cannot keep a session forever.
/// </remarks>
public sealed class RefreshTokenGrant
{
    private const string GrantName = "refresh_token";

    private readonly ClientAuthenticator _authenticator;
    private readonly DpopTokenCheck _dpop;
    private readonly ITokenStore _tokens;
    private readonly IUserStore _users;
    private readonly ITokenSigner _signer;
    private readonly IAuditLog _audit;
    private readonly ISecurityAlerts _alerts;
    private readonly TimeProvider _time;

    public RefreshTokenGrant(
        ClientAuthenticator authenticator,
        DpopTokenCheck dpop,
        ITokenStore tokens,
        IUserStore users,
        ITokenSigner signer,
        IAuditLog audit,
        ISecurityAlerts alerts,
        TimeProvider time)
    {
        _authenticator = authenticator;
        _dpop = dpop;
        _tokens = tokens;
        _users = users;
        _signer = signer;
        _audit = audit;
        _alerts = alerts;
        _time = time;
    }

    public async Task<Result<TokenResponse>> HandleAsync(
        RequestContext context,
        RefreshTokenRequest request,
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
                    ["client_id"] = request.ClientId is { Length: > 128 } id ? id[..128] : request.ClientId ?? string.Empty,
                    ["error"] = result.Error.Code,
                    ["reason"] = result.Error.AuditDetail,
                },
                cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    private async Task<Result<TokenResponse>> IssueAsync(
        RequestContext context,
        RefreshTokenRequest request,
        CancellationToken cancellationToken)
    {
        if (context.Tenant.Status != TenantStatus.Active)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidClient("tenant suspended"));
        }

        var authentication = await _authenticator
            .AuthenticateAsync(context.Tenant.Id, context.Issuer, request.ClientId, request.ClientSecret, request.ClientAssertion, cancellationToken)
            .ConfigureAwait(false);
        if (!authentication.IsSuccess)
        {
            return Result.Failure<TokenResponse>(authentication.Error);
        }

        var client = authentication.Value;
        if (!client.IsGrantAllowed(GrantType.RefreshToken))
        {
            return Result.Failure<TokenResponse>(OAuthError.UnauthorizedClient("refresh_token not allowed"));
        }

        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidRequest("refresh_token missing"));
        }

        var requestedScopes = ScopeParser.Parse(request.Scope);
        if (requestedScopes is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidScope("malformed scope"));
        }

        var audience = client.ResolveUserAudience(request.Resource, UserInfoEndpoint.AudienceFor(context.Issuer));
        if (audience is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidTarget("resource missing or not allowed"));
        }

        // Last before the rotation: the replay check is a database write (D24 to D26).
        var dpop = await _dpop.CheckAsync(context, client, request.DpopProof, cancellationToken).ConfigureAwait(false);
        if (!dpop.IsSuccess)
        {
            return Result.Failure<TokenResponse>(dpop.Error);
        }

        var keyThumbprint = dpop.Value;
        var now = _time.GetUtcNow();
        var hash = TokenHash.Compute(request.RefreshToken);

        RefreshToken? used;
        TokenResponse? response = null;
        TokenFamily? family = null;
        // Stryker disable Boolean : the flags are read only after a match, and a match sets both.
        var scopeTooWide = false;
        var userDisabled = false;
        // Stryker restore Boolean
        var transaction = await _tokens.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (transaction.ConfigureAwait(false))
        {
            used = await _tokens.UseRefreshTokenAsync(new RefreshRotation(context.Tenant.Id, hash, client.Id, now, keyThumbprint), cancellationToken)
                .ConfigureAwait(false);

            if (used is not null)
            {
                family = await _tokens.FindFamilyAsync(context.Tenant.Id, used.FamilyId, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("A refresh token without its family.");

                // Refresh can keep or reduce the scope. It can never add to it.
                var scopes = requestedScopes.Count == 0 ? family.Scope.Split(' ') : requestedScopes;
                var user = await _users.FindByIdAsync(context.Tenant.Id, family.UserId, cancellationToken).ConfigureAwait(false);
                scopeTooWide = !family.IsScopeAllowed(scopes);
                userDisabled = user is not { Status: UserStatus.Active };
                if (!scopeTooWide && !userDisabled)
                {
                    response = await RotateAsync(context, client, used, family, scopes, audience, keyThumbprint, now, cancellationToken).ConfigureAwait(false);
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                }
            }
        }

        if (used is null)
        {
            // Outside the transaction, so a reuse revocation and its audit events are never rolled back.
            return await ExplainFailureAsync(context, client, hash, keyThumbprint, now, cancellationToken).ConfigureAwait(false);
        }

        if (userDisabled)
        {
            // Threat model, Refresh flow: a disabled account ends the family.
            await RevokeAsync(context, family!, FamilyRevocationReason.UserDisabled, now, cancellationToken).ConfigureAwait(false);
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("user disabled"));
        }

        if (scopeTooWide)
        {
            // The token was not used: the transaction rolled back, so the client can retry with a valid scope.
            return Result.Failure<TokenResponse>(OAuthError.InvalidScope("scope wider than the original grant"));
        }

        await WriteAuditAsync(
            context,
            AuditEventTypes.RefreshRotated,
            client.Id,
            family!.UserId,
            family.Id,
            RotatedData(response!, audience, keyThumbprint),
            cancellationToken).ConfigureAwait(false);

        return Result.Success(response!);
    }

    /// <summary>Runs in the rotation transaction: signs the access token, stores the next refresh token, moves the idle limit.</summary>
    private async Task<TokenResponse> RotateAsync(
        RequestContext context,
        Client client,
        RefreshToken used,
        TokenFamily family,
        IReadOnlyList<string> scopes,
        string audience,
        string? keyThumbprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var lifetimes = client.ResolveLifetimes(context.Tenant.Settings);
        var accessToken = await _signer.SignAccessTokenAsync(
            context.Tenant.Id,
            new AccessTokenClaims(
                context.Issuer,
                family.UserId.ToString(),
                audience,
                client.ClientId,
                scopes,
                now,
                now + lifetimes.AccessToken,
                Guid.NewGuid().ToString("N"),
                KeyThumbprint: keyThumbprint,
                FamilyId: family.Id),
            cancellationToken).ConfigureAwait(false);

        var refreshToken = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var next = RefreshToken.Create(Guid.CreateVersion7(), context.Tenant.Id, family.Id, TokenHash.Compute(refreshToken), now);
        await _tokens.CompleteRotationAsync(used, next, lifetimes.RefreshIdle, now, cancellationToken).ConfigureAwait(false);

        return new TokenResponse(
            accessToken,
            TokenResponse.TypeFor(keyThumbprint),
            (int)lifetimes.AccessToken.TotalSeconds,
            string.Join(' ', scopes),
            refreshToken);
    }

    /// <summary>
    /// The rotation matched no row. The caller always gets the same <c>invalid_grant</c> (D5). A token that was already
    /// used is reuse: its whole family is revoked and an alert is raised, whoever presented it.
    /// </summary>
    private async Task<Result<TokenResponse>> ExplainFailureAsync(
        RequestContext context,
        Client client,
        TokenHash hash,
        string? keyThumbprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var token = await _tokens.FindRefreshTokenAsync(context.Tenant.Id, hash, cancellationToken).ConfigureAwait(false);
        if (token is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("unknown refresh token"));
        }

        var family = await _tokens.FindFamilyAsync(context.Tenant.Id, token.FamilyId, cancellationToken).ConfigureAwait(false);
        if (family is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("family missing"));
        }

        if (token.UsedAt is not null)
        {
            var revoked = await RevokeAsync(context, family, FamilyRevocationReason.ReuseDetected, now, cancellationToken).ConfigureAwait(false);
            var data = new Dictionary<string, string>
            {
                ["client_id"] = client.ClientId,
                ["family_revoked"] = revoked ? "yes" : "already revoked",
            };
            await WriteAuditAsync(context, AuditEventTypes.RefreshReuseDetected, family.ClientPk, family.UserId, family.Id, data, cancellationToken)
                .ConfigureAwait(false);
            _alerts.Raise(AuditEventTypes.RefreshReuseDetected, context.Tenant.Id, data);
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("refresh token reused"));
        }

        if (family.ClientPk != client.Id)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("refresh token of another client"));
        }

        if (family.RevokedAt is not null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("family revoked"));
        }

        // D24: the rotation statement matched no row because the key differs. The token is not used up.
        if (family.DpopKeyThumbprint is { } boundKey && !string.Equals(boundKey, keyThumbprint, StringComparison.Ordinal))
        {
            return Result.Failure<TokenResponse>(keyThumbprint is null
                ? OAuthError.InvalidDpopProof("proof required for a bound refresh token")
                : OAuthError.InvalidGrant("DPoP key differs from the family's key"));
        }

        return Result.Failure<TokenResponse>(OAuthError.InvalidGrant("family expired"));
    }

    private static Dictionary<string, string> RotatedData(TokenResponse response, string audience, string? keyThumbprint)
    {
        var data = new Dictionary<string, string> { ["scope"] = response.Scope, ["aud"] = audience };
        if (keyThumbprint is not null)
        {
            data["dpop_jkt"] = keyThumbprint;
        }

        return data;
    }

    private async Task<bool> RevokeAsync(
        RequestContext context,
        TokenFamily family,
        FamilyRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var revoked = await _tokens.RevokeFamilyAsync(context.Tenant.Id, family.Id, reason, now, cancellationToken).ConfigureAwait(false);
        if (revoked)
        {
            await WriteAuditAsync(
                context,
                AuditEventTypes.FamilyRevoked,
                family.ClientPk,
                family.UserId,
                family.Id,
                new Dictionary<string, string> { ["reason"] = reason == FamilyRevocationReason.ReuseDetected ? "reuse_detected" : "user_disabled" },
                cancellationToken).ConfigureAwait(false);
        }

        return revoked;
    }

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
