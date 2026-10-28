using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;

namespace Heimdall.Application.Tokens;

/// <param name="ClientId">From the Basic header.</param>
/// <param name="ClientSecret">From the Basic header.</param>
/// <param name="Scope">The <c>scope</c> parameter, or null.</param>
/// <param name="Resource">The <c>resource</c> parameter (RFC 8707), or null.</param>
/// <param name="DpopProof">The DPoP header, or null.</param>
public sealed record ClientCredentialsRequest(
    string? ClientId, string? ClientSecret, string? Scope, string? Resource, string? DpopProof = null, string? ClientAssertion = null);

/// <summary>
/// The <c>client_credentials</c> grant at /token. There is no user and no refresh token (OAuth 2.1).
/// The client secret is the only defense, so every check fails closed.
/// </summary>
public sealed class ClientCredentialsGrant
{
    // OpenID Connect scopes describe a user. A client_credentials token has no user.
    private static readonly string[] UserScopes = ["openid", "profile", "email", "address", "phone", "offline_access"];

    private readonly ClientAuthenticator _authenticator;
    private readonly DpopTokenCheck _dpop;
    private readonly ITokenSigner _signer;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public ClientCredentialsGrant(ClientAuthenticator authenticator, DpopTokenCheck dpop, ITokenSigner signer, IAuditLog audit, TimeProvider time)
    {
        _authenticator = authenticator;
        _dpop = dpop;
        _signer = signer;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<TokenResponse>> HandleAsync(
        RequestContext context,
        ClientCredentialsRequest request,
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
                new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    // The caller controls this value. Cap it so a failed request cannot flood the audit log.
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
        ClientCredentialsRequest request,
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

        if (!client.IsGrantAllowed(GrantType.ClientCredentials))
        {
            return Result.Failure<TokenResponse>(OAuthError.UnauthorizedClient("client_credentials not allowed"));
        }

        var requested = ScopeParser.Parse(request.Scope);
        if (requested is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidScope("malformed scope"));
        }

        // No scope requested: issue the client's allowed scopes (RFC 6749, section 3.3 allows a default).
        var scopes = requested.Count == 0 ? client.AllowedScopes : requested;

        if (scopes.Any(s => UserScopes.Contains(s, StringComparer.Ordinal)))
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidScope("user scope in client_credentials"));
        }

        // Reject, do not silently reduce. A client that asks for too much has a configuration error.
        if (client.FilterAllowedScopes(scopes).Count != scopes.Count)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidScope("scope not allowed for client"));
        }

        var audience = client.ResolveAudience(request.Resource);
        if (audience is null)
        {
            return Result.Failure<TokenResponse>(OAuthError.InvalidTarget("resource missing or not allowed"));
        }

        // Last before signing: the replay check is a database write (D24 to D26).
        var dpop = await _dpop.CheckAsync(context, client, request.DpopProof, cancellationToken).ConfigureAwait(false);
        if (!dpop.IsSuccess)
        {
            return Result.Failure<TokenResponse>(dpop.Error);
        }

        var lifetimes = client.ResolveLifetimes(context.Tenant.Settings);
        var now = _time.GetUtcNow();
        var claims = new AccessTokenClaims(
            Issuer: context.Issuer,
            Subject: client.ClientId,
            Audience: audience,
            ClientId: client.ClientId,
            Scopes: scopes,
            IssuedAt: now,
            ExpiresAt: now + lifetimes.AccessToken,
            JwtId: Guid.NewGuid().ToString("N"),
            KeyThumbprint: dpop.Value);

        var accessToken = await _signer
            .SignAccessTokenAsync(context.Tenant.Id, claims, cancellationToken)
            .ConfigureAwait(false);

        var issued = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["jti"] = claims.JwtId,
            ["aud"] = audience,
            ["scope"] = string.Join(' ', scopes),
        };
        if (dpop.Value is { } keyThumbprint)
        {
            issued["dpop_jkt"] = keyThumbprint;
        }

        await WriteAuditAsync(context, AuditEventTypes.TokenIssued, client.Id, issued, cancellationToken).ConfigureAwait(false);

        return Result.Success(new TokenResponse(
            accessToken,
            TokenResponse.TypeFor(dpop.Value),
            (int)lifetimes.AccessToken.TotalSeconds,
            string.Join(' ', scopes)));
    }

    // Stryker disable once Equality : at that exact length, value[..maxLength] equals value.
    private static string Truncate(string? value, int maxLength) =>
        value is null ? string.Empty : value.Length <= maxLength ? value : value[..maxLength];

    private Task WriteAuditAsync(
        RequestContext context,
        string type,
        Guid? clientPk,
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
                clientPk: clientPk,
                data: data),
            cancellationToken);
}
