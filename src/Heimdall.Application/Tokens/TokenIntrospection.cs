using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.UserInfo;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;

namespace Heimdall.Application.Tokens;

/// <param name="ClientId">From the Basic header.</param>
/// <param name="ClientSecret">From the Basic header. A public client has none, and it is refused (D36).</param>
/// <param name="Token">The <c>token</c> parameter.</param>
public sealed record IntrospectionRequest(string? ClientId, string? ClientSecret, string? Token);

/// <summary>
/// An introspection answer (RFC 7662, section 2.2, D39). An inactive answer has only <see cref="Active"/>, so it shows
/// nothing about why.
/// </summary>
/// <param name="TokenType"><c>Bearer</c> or <c>DPoP</c> for an access token, null for a refresh token.</param>
/// <param name="KeyThumbprint">The <c>cnf.jkt</c> of a DPoP-bound token (RFC 9449, section 6.2), or null.</param>
public sealed record IntrospectionResult(
    bool Active,
    string? Scope = null,
    string? ClientId = null,
    string? Subject = null,
    string? Audience = null,
    string? Issuer = null,
    DateTimeOffset? ExpiresAt = null,
    DateTimeOffset? IssuedAt = null,
    string? TokenType = null,
    string? KeyThumbprint = null)
{
    public static IntrospectionResult Inactive { get; } = new(false);
}

/// <summary>
/// <c>POST /oauth/v1/introspect</c> (RFC 7662, D36 to D39). It tells a resource server whether a token is active now:
/// valid, unexpired, and in a family that nobody revoked.
/// </summary>
/// <remarks>
/// A JWS has two dots and a refresh token has none, so the format names the kind of token, and
/// <c>token_type_hint</c> is not needed. Every token that the caller may not see gets the same inactive answer as an
/// unknown token (D37).
/// </remarks>
public sealed class TokenIntrospection
{
    private readonly ClientAuthenticator _authenticator;
    private readonly IAccessTokenValidator _validator;
    private readonly ITokenStore _tokens;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public TokenIntrospection(
        ClientAuthenticator authenticator,
        IAccessTokenValidator validator,
        ITokenStore tokens,
        IAuditLog audit,
        TimeProvider time)
    {
        _authenticator = authenticator;
        _validator = validator;
        _tokens = tokens;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<IntrospectionResult>> IntrospectAsync(
        RequestContext context,
        IntrospectionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        var authentication = await _authenticator
            .AuthenticateAsync(context.Tenant.Id, request.ClientId, request.ClientSecret, cancellationToken)
            .ConfigureAwait(false);

        // D36: a public client passes ClientAuthenticator with its client_id alone. That proves nothing here.
        var error = !authentication.IsSuccess
            ? authentication.Error
            : authentication.Value.Type != ClientType.Confidential
                ? OAuthError.InvalidClient("public client at introspection")
                : null;
        if (error is not null)
        {
            // Audited like a failed authentication at /token and /revoke, so /introspect is no secret-guessing door.
            await _audit.WriteAsync(
                AuditEvent.Record(
                    Guid.CreateVersion7(),
                    context.Tenant.Id,
                    AuditEventTypes.IntrospectionRefused,
                    context.CorrelationId,
                    _time.GetUtcNow(),
                    context.SourceIp,
                    data: new Dictionary<string, string>
                    {
                        ["client_id"] = request.ClientId is { Length: > 128 } id ? id[..128] : request.ClientId ?? string.Empty,
                        ["error"] = error.Code,
                        ["reason"] = error.AuditDetail,
                    }),
                cancellationToken).ConfigureAwait(false);
            return Result.Failure<IntrospectionResult>(error);
        }

        if (string.IsNullOrEmpty(request.Token))
        {
            return Result.Failure<IntrospectionResult>(OAuthError.InvalidRequest("token missing"));
        }

        var caller = authentication.Value;
        var now = _time.GetUtcNow();
        var result = request.Token.Contains('.', StringComparison.Ordinal)
            ? await AccessTokenAsync(context, caller, request.Token, now, cancellationToken).ConfigureAwait(false)
            : await RefreshTokenAsync(context, caller, request.Token, now, cancellationToken).ConfigureAwait(false);
        return Result.Success(result);
    }

    /// <summary>D38: signature, issuer, expiry, the caller's right to see it (D37), then one read of its family.</summary>
    private async Task<IntrospectionResult> AccessTokenAsync(
        RequestContext context,
        Client caller,
        string token,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var verified = await _validator.ValidateAsync(context.Tenant.Id, token, cancellationToken).ConfigureAwait(false);
        if (verified is null
            || !string.Equals(verified.Issuer, context.Issuer, StringComparison.Ordinal)
            || verified.ExpiresAt <= now
            || !caller.MayIntrospect(verified.Audience, verified.ClientId))
        {
            return IntrospectionResult.Inactive;
        }

        // A client_credentials token has no family. A user grant's token is as active as its family.
        if (verified.FamilyId is { } familyId)
        {
            var family = await _tokens.FindFamilyAsync(context.Tenant.Id, familyId, cancellationToken).ConfigureAwait(false);
            if (family is not { RevokedAt: null })
            {
                return IntrospectionResult.Inactive;
            }
        }

        return new IntrospectionResult(
            true,
            verified.Scopes.Count > 0 ? string.Join(' ', verified.Scopes) : null,
            verified.ClientId,
            verified.Subject,
            verified.Audience,
            verified.Issuer,
            verified.ExpiresAt,
            verified.IssuedAt,
            TokenResponse.TypeFor(verified.KeyThumbprint),
            verified.KeyThumbprint);
    }

    /// <summary>D38: an unused refresh token of the caller's own family, unrevoked and inside both limits.</summary>
    private async Task<IntrospectionResult> RefreshTokenAsync(
        RequestContext context,
        Client caller,
        string token,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var refresh = await _tokens.FindRefreshTokenAsync(context.Tenant.Id, TokenHash.Compute(token), cancellationToken).ConfigureAwait(false);
        if (refresh is not { UsedAt: null })
        {
            return IntrospectionResult.Inactive;
        }

        var family = await _tokens.FindFamilyAsync(context.Tenant.Id, refresh.FamilyId, cancellationToken).ConfigureAwait(false);
        if (family is null || family.ClientPk != caller.Id || !family.IsActive(now))
        {
            return IntrospectionResult.Inactive;
        }

        return new IntrospectionResult(
            true,
            family.Scope,
            caller.ClientId,
            family.UserId.ToString(),
            Issuer: context.Issuer,
            ExpiresAt: family.IdleExpiresAt,
            IssuedAt: refresh.CreatedAt);
    }
}
