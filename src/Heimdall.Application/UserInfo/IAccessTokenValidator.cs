namespace Heimdall.Application.UserInfo;

/// <summary>The claims of an access token whose format, header, and signature are valid.</summary>
/// <remarks>The validator does not check <c>iss</c>, <c>aud</c>, or <c>exp</c>. <see cref="UserInfoService"/> does.</remarks>
public sealed record VerifiedAccessToken(
    string Issuer,
    string Subject,
    string Audience,
    string ClientId,
    IReadOnlyList<string> Scopes,
    DateTimeOffset ExpiresAt);

/// <summary>Checks an access token that this tenant signed (RFC 9068).</summary>
public interface IAccessTokenValidator
{
    /// <summary>
    /// Returns the claims when the token is a compact JWS with <c>alg</c> = RS256 and <c>typ</c> = <c>at+jwt</c>, its
    /// <c>kid</c> is in the tenant's published keys, and the signature is valid. Returns null on any failure.
    /// </summary>
    ValueTask<VerifiedAccessToken?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken);
}
