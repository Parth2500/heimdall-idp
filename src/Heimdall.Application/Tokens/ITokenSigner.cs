namespace Heimdall.Application.Tokens;

/// <summary>
/// The claims of an access token (RFC 9068). The signer adds the header (<c>alg</c> = RS256, <c>kid</c>,
/// <c>typ</c> = <c>at+jwt</c>).
/// </summary>
/// <param name="KeyThumbprint">The DPoP key that the token is bound to (<c>cnf.jkt</c>, RFC 9449), or null for a bearer token.</param>
/// <param name="FamilyId">
/// The token family of a user grant (the <c>fid</c> claim, D29), or null for <c>client_credentials</c>. The value is
/// opaque and authenticates nothing. Introspection uses it to see that a sign-out or a reuse revoked the family.
/// </param>
public sealed record AccessTokenClaims(
    string Issuer,
    string Subject,
    string Audience,
    string ClientId,
    IReadOnlyList<string> Scopes,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string JwtId,
    DateTimeOffset? AuthTime = null,
    string? KeyThumbprint = null,
    Guid? FamilyId = null);

/// <summary>
/// The claims of an OpenID Connect ID token (OpenID Connect Core, section 2). The audience is the client. The signer
/// adds the header (<c>alg</c> = RS256, <c>kid</c>, <c>typ</c> = <c>JWT</c>).
/// </summary>
/// <param name="Sid">The public session ID (D29), or null for a code from before it existed.</param>
public sealed record IdTokenClaims(
    string Issuer,
    string Subject,
    string ClientId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset AuthTime,
    string? Nonce,
    string? Sid = null);

/// <summary>
/// The claims of a logout token (Back-Channel Logout 1.0, section 2.4, D34). The audience is the client. The signer adds
/// the header (<c>alg</c> = RS256, <c>kid</c>, <c>typ</c> = <c>logout+jwt</c>) and the back-channel logout event.
/// </summary>
public sealed record LogoutTokenClaims(
    string Issuer,
    string Subject,
    string ClientId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string JwtId,
    string Sid);

public interface ITokenSigner
{
    /// <summary>Signs with the active key of the tenant (D8, D19). Returns the compact JWT.</summary>
    Task<string> SignAccessTokenAsync(Guid tenantId, AccessTokenClaims claims, CancellationToken cancellationToken);

    /// <summary>Signs an ID token with the active key of the tenant. Returns the compact JWT.</summary>
    Task<string> SignIdTokenAsync(Guid tenantId, IdTokenClaims claims, CancellationToken cancellationToken);

    /// <summary>Signs a logout token with the active key of the tenant (D34). Returns the compact JWT.</summary>
    Task<string> SignLogoutTokenAsync(Guid tenantId, LogoutTokenClaims claims, CancellationToken cancellationToken);
}
