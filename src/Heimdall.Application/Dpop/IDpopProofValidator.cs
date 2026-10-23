using Heimdall.Application.Common;

namespace Heimdall.Application.Dpop;

/// <summary>The proof algorithms that Heimdall accepts (D25). Discovery and the DPoP challenge publish this list.</summary>
public static class DpopAlgorithms
{
    public static readonly IReadOnlyList<string> Supported = ["ES256", "RS256"];
}

/// <summary>The request that a DPoP proof must match.</summary>
/// <param name="Method">The HTTP method, as the server received it.</param>
/// <param name="Url">The endpoint URL in the tenant: the issuer and the path. The proof's <c>htu</c> must equal it.</param>
/// <param name="AccessToken">At a resource, the presented access token, so <c>ath</c> can be checked. Null at /token.</param>
public sealed record DpopRequest(string Method, Uri Url, string? AccessToken = null);

/// <summary>A DPoP proof that passed every rule of D25. The replay check (D26) comes after it.</summary>
/// <param name="KeyThumbprint">The RFC 7638 thumbprint of the proof's public key. A bound token carries it as <c>cnf.jkt</c>.</param>
/// <param name="Jti">The proof's unique ID.</param>
/// <param name="IssuedAt">The proof's <c>iat</c>.</param>
public sealed record DpopProof(string KeyThumbprint, string Jti, DateTimeOffset IssuedAt);

/// <summary>Checks a DPoP proof (RFC 9449, section 4.3) against the request it came with. The check reads no database.</summary>
public interface IDpopProofValidator
{
    /// <summary>The proof, or <c>invalid_dpop_proof</c> with the failed rule in the audit detail.</summary>
    Result<DpopProof> Validate(string proof, DpopRequest request);
}
