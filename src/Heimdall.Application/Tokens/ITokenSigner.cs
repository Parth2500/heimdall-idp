namespace Heimdall.Application.Tokens;

/// <summary>
/// The claims of an access token (RFC 9068). The signer adds the header (<c>alg</c> = RS256, <c>kid</c>,
/// <c>typ</c> = <c>at+jwt</c>).
/// </summary>
public sealed record AccessTokenClaims(
    string Issuer,
    string Subject,
    string Audience,
    string ClientId,
    IReadOnlyList<string> Scopes,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string JwtId);

public interface ITokenSigner
{
    /// <summary>Signs with the active key of the tenant (D8, D19). Returns the compact JWT.</summary>
    Task<string> SignAccessTokenAsync(Guid tenantId, AccessTokenClaims claims, CancellationToken cancellationToken);
}
