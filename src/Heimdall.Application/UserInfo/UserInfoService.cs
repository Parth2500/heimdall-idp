using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Users;

namespace Heimdall.Application.UserInfo;

/// <summary>The userinfo endpoint's path and the audience that a token for it carries.</summary>
public static class UserInfoEndpoint
{
    public const string Path = "/oauth/v1/userinfo";

    /// <summary>The <c>aud</c> value of a token for the userinfo endpoint: the endpoint's URL in the tenant.</summary>
    public static string AudienceFor(string issuer) => issuer + Path;
}

/// <summary>The claims that the granted scopes release. Null members are left out of the response.</summary>
/// <param name="Subject">The <c>sub</c>. It equals the <c>sub</c> of the ID token.</param>
/// <param name="Email">Released for the <c>email</c> scope.</param>
/// <param name="EmailVerified">
/// Released with <see cref="Email"/>. Always false: Heimdall has no email verification yet (threat model, out of scope).
/// </param>
public sealed record UserInfoClaims(string Subject, string? Email, bool? EmailVerified);

/// <summary>
/// <c>GET /oauth/v1/userinfo</c> (OpenID Connect Core, section 5.3). The caller sends a bearer access token for the
/// userinfo endpoint. Heimdall loads the user on each call, so a disabled user gets no data, even with a valid token.
/// </summary>
/// <remarks>
/// Every token failure is the same <c>invalid_token</c> (D5). The reason goes to the log, not the audit log: a bad
/// token costs no database write. A successful call writes an audit event (threat model, /userinfo, Repudiation).
/// </remarks>
public sealed class UserInfoService
{
    public const string InvalidTokenCode = "invalid_token";
    public const string InsufficientScopeCode = "insufficient_scope";

    private readonly IAccessTokenValidator _validator;
    private readonly IUserStore _users;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public UserInfoService(IAccessTokenValidator validator, IUserStore users, IAuditLog audit, TimeProvider time)
    {
        _validator = validator;
        _users = users;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<UserInfoClaims>> GetAsync(RequestContext context, string accessToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(accessToken);

        var token = await _validator.ValidateAsync(context.Tenant.Id, accessToken, cancellationToken).ConfigureAwait(false);
        if (token is null)
        {
            return Invalid("format, header, or signature");
        }

        // The keys are per tenant, so a signature check already ties the token to this tenant. iss is checked too (D19).
        if (!string.Equals(token.Issuer, context.Issuer, StringComparison.Ordinal))
        {
            return Invalid("iss is not this tenant");
        }

        // A token for a resource server cannot read user claims here (D22).
        if (!string.Equals(token.Audience, UserInfoEndpoint.AudienceFor(context.Issuer), StringComparison.Ordinal))
        {
            return Invalid("aud is not the userinfo endpoint");
        }

        // No clock skew: Heimdall issued the token, and its servers share one time source.
        if (_time.GetUtcNow() >= token.ExpiresAt)
        {
            return Invalid("expired");
        }

        // A client_credentials token has a client as its subject, not a user. It never matches a user ID.
        if (!Guid.TryParse(token.Subject, out var userId))
        {
            return Invalid("sub is not a user");
        }

        var user = await _users.FindByIdAsync(context.Tenant.Id, userId, cancellationToken).ConfigureAwait(false);
        if (user is not { Status: UserStatus.Active })
        {
            return Invalid(user is null ? "unknown user" : "user disabled");
        }

        // OpenID Connect Core, section 5.3: the token must come from an OpenID request.
        if (!token.Scopes.Contains("openid", StringComparer.Ordinal))
        {
            return Result.Failure<UserInfoClaims>(new OAuthError(InsufficientScopeCode, "openid scope missing"));
        }

        // The server maps scopes to claims. A claim that no granted scope allows is never in the response.
        var releaseEmail = token.Scopes.Contains("email", StringComparer.Ordinal);
        var claims = new UserInfoClaims(user.Id.ToString(), releaseEmail ? user.Email : null, releaseEmail ? false : null);

        // Claim values are not in the audit log. Only the scopes that released them are.
        await _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                AuditEventTypes.UserInfoRead,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: user.Id,
                data: new Dictionary<string, string>
                {
                    ["client_id"] = token.ClientId,
                    ["scope"] = string.Join(' ', token.Scopes),
                }),
            cancellationToken).ConfigureAwait(false);

        return Result.Success(claims);
    }

    private static Result<UserInfoClaims> Invalid(string reason) =>
        Result.Failure<UserInfoClaims>(new OAuthError(InvalidTokenCode, reason));
}
