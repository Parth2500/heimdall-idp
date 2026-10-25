namespace Heimdall.Application.Logout;

/// <summary>The claims of an <c>id_token_hint</c> whose format, header, and signature are valid.</summary>
/// <remarks>The validator does not check <c>iss</c>, <c>aud</c>, or <c>exp</c>. <see cref="LogoutService"/> checks the first two and ignores <c>exp</c> (D30).</remarks>
/// <param name="Audiences">The <c>aud</c> claim: one string, or each value of an array.</param>
/// <param name="Sid">The <c>sid</c> claim (D29), or null.</param>
public sealed record VerifiedIdTokenHint(string Issuer, string Subject, IReadOnlyList<string> Audiences, string? Sid);

/// <summary>Checks an ID token that this tenant signed, sent back as <c>id_token_hint</c> (RP-Initiated Logout 1.0, section 2).</summary>
public interface IIdTokenHintValidator
{
    /// <summary>
    /// Returns the claims when the token is a compact JWS with <c>alg</c> = RS256 and <c>typ</c> = <c>JWT</c>, its
    /// <c>kid</c> is in the tenant's published keys (a retired key too, until it leaves the JWKS), and the signature is
    /// valid. Returns null on any failure.
    /// </summary>
    ValueTask<VerifiedIdTokenHint?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken);
}
