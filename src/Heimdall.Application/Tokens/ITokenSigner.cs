namespace Heimdall.Application.Tokens;

/// <summary>
/// The claims of an access token (RFC 9068). The signer adds the header (<c>alg</c> = RS256, <c>kid</c>,
/// <c>typ</c> = <c>at+jwt</c>).
/// </summary>
/// <param name="KeyThumbprint">The DPoP key that the token is bound to (<c>cnf.jkt</c>, RFC 9449), or null for a bearer token.</param>
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
    string? KeyThumbprint = null);

/// <summary>
/// The claims of an OpenID Connect ID token (OpenID Connect Core, section 2). The audience is the client. The signer
/// adds the header (<c>alg</c> = RS256, <c>kid</c>, <c>typ</c> = <c>JWT</c>).
/// </summary>
public sealed record IdTokenClaims(
    string Issuer,
    string Subject,
    string ClientId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset AuthTime,
    string? Nonce);

public interface ITokenSigner
{
    /// <summary>Signs with the active key of the tenant (D8, D19). Returns the compact JWT.</summary>
    Task<string> SignAccessTokenAsync(Guid tenantId, AccessTokenClaims claims, CancellationToken cancellationToken);

    /// <summary>Signs an ID token with the active key of the tenant. Returns the compact JWT.</summary>
    Task<string> SignIdTokenAsync(Guid tenantId, IdTokenClaims claims, CancellationToken cancellationToken);
}
