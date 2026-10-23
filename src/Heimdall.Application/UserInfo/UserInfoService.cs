using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
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

/// <summary>The authentication scheme of the <c>Authorization</c> header.</summary>
public enum TokenScheme
{
    /// <summary><c>Authorization: Bearer</c> (RFC 6750).</summary>
    Bearer,

    /// <summary><c>Authorization: DPoP</c>, with a proof in the <c>DPoP</c> header (RFC 9449, section 7.1).</summary>
    Dpop,
}

/// <summary>A userinfo request as the endpoint received it.</summary>
/// <param name="AccessToken">The token from the <c>Authorization</c> header.</param>
/// <param name="Scheme">The scheme that the token came with.</param>
/// <param name="Method">The HTTP method. A DPoP proof must name it in <c>htm</c>.</param>
/// <param name="DpopProof">The one <c>DPoP</c> header, or null.</param>
public sealed record UserInfoRequest(string AccessToken, TokenScheme Scheme, string Method, string? DpopProof = null);

/// <summary>
/// <c>GET /oauth/v1/userinfo</c> (OpenID Connect Core, section 5.3). The caller sends an access token for the
/// userinfo endpoint. Heimdall loads the user on each call, so a disabled user gets no data, even with a valid token.
/// A DPoP-bound token works only with the DPoP scheme and a proof from its key (D28).
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
    private readonly IDpopProofValidator _proofs;
    private readonly IDpopReplayStore _replay;
    private readonly IUserStore _users;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public UserInfoService(
        IAccessTokenValidator validator,
        IDpopProofValidator proofs,
        IDpopReplayStore replay,
        IUserStore users,
        IAuditLog audit,
        TimeProvider time)
    {
        _validator = validator;
        _proofs = proofs;
        _replay = replay;
        _users = users;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<UserInfoClaims>> GetAsync(RequestContext context, UserInfoRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrEmpty(request.AccessToken);

        var token = await _validator.ValidateAsync(context.Tenant.Id, request.AccessToken, cancellationToken).ConfigureAwait(false);
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

        // D28: the binding before any user data. The replay check is a database write, so it runs after the cheap checks.
        if (await CheckBindingAsync(context, request, token, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return Result.Failure<UserInfoClaims>(refused);
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

    /// <summary>
    /// RFC 9449, section 7: a bound token needs the DPoP scheme and a valid, unused proof from its key. A bound token sent
    /// as a bearer token fails, or the binding would protect nothing (D28). An unbound token with the DPoP scheme fails
    /// too, so a client cannot claim a binding that the token does not have.
    /// </summary>
    /// <returns>The error, or null when the binding holds.</returns>
    private async Task<OAuthError?> CheckBindingAsync(
        RequestContext context,
        UserInfoRequest request,
        VerifiedAccessToken token,
        CancellationToken cancellationToken)
    {
        if (token.KeyThumbprint is not { } boundKey)
        {
            return request.Scheme == TokenScheme.Dpop ? new OAuthError(InvalidTokenCode, "unbound token with the DPoP scheme") : null;
        }

        if (request.Scheme != TokenScheme.Dpop)
        {
            return new OAuthError(InvalidTokenCode, "bound token sent as a bearer token");
        }

        if (request.DpopProof is null)
        {
            return OAuthError.InvalidDpopProof("proof missing");
        }

        var url = new Uri(context.Issuer + UserInfoEndpoint.Path);
        var proof = _proofs.Validate(request.DpopProof, new DpopRequest(request.Method, url, request.AccessToken));
        if (!proof.IsSuccess)
        {
            return proof.Error;
        }

        if (!string.Equals(proof.Value.KeyThumbprint, boundKey, StringComparison.Ordinal))
        {
            return OAuthError.InvalidDpopProof("proof key differs from cnf.jkt");
        }

        return await _replay.TryUseAsync(context.Tenant.Id, proof.Value, cancellationToken).ConfigureAwait(false)
            ? null
            : OAuthError.InvalidDpopProof("proof replayed");
    }

    private static Result<UserInfoClaims> Invalid(string reason) =>
        Result.Failure<UserInfoClaims>(new OAuthError(InvalidTokenCode, reason));
}
