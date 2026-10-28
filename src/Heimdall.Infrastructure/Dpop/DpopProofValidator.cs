using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.Keys;
using Heimdall.Infrastructure.Keys;

namespace Heimdall.Infrastructure.Dpop;

/// <summary>
/// Checks a DPoP proof (RFC 9449, section 4.3) by the rules of D25. The cheap checks run first: size, format, header,
/// and claims. The signature check runs last, and nothing here reads the database.
/// </summary>
/// <remarks>
/// The algorithm comes from <see cref="SupportedAlgorithms"/>, never from the proof alone, and it must match the key type.
/// The proof's <c>jwk</c> must be a public key: a private member, another curve, or a short RSA key fails.
/// </remarks>
internal sealed class DpopProofValidator : IDpopProofValidator
{
    /// <summary>The values of <c>dpop_signing_alg_values_supported</c> in discovery.</summary>
    public static readonly IReadOnlyList<string> SupportedAlgorithms = DpopAlgorithms.Supported;

    /// <summary>The largest difference between the proof's <c>iat</c> and the server time, in either direction.</summary>
    public static readonly TimeSpan MaxClockDifference = TimeSpan.FromSeconds(60);

    // A proof with an RSA-4096 key is under 2 KB. The limit stops a large value before any decoding.
    private const int MaxProofLength = 4096;
    private const int MaxJtiLength = 256;

    // Members of a private JWK (RFC 7518, section 6). A public key has none of them.
    private static readonly string[] PrivateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    private readonly TimeProvider _time;

    public DpopProofValidator(TimeProvider time)
    {
        _time = time;
    }

    public Result<DpopProof> Validate(string proof, DpopRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrEmpty(proof) || proof.Length > MaxProofLength)
        {
            return Fail("proof missing or too long");
        }

        var parts = proof.Split('.');
        if (parts.Length != 3)
        {
            return Fail("proof is not a compact JWS");
        }

        using var header = Jws.DecodeJson(parts[0]);
        if (header?.RootElement is not { ValueKind: JsonValueKind.Object } h)
        {
            return Fail("header is not a JSON object");
        }

        if (!IsDpopType(h))
        {
            return Fail("typ is not dpop+jwt");
        }

        if (h.TryGetProperty("crit", out _))
        {
            return Fail("crit header");
        }

        if (!Jws.IsString(h, "alg", out var alg) || !SupportedAlgorithms.Contains(alg, StringComparer.Ordinal))
        {
            return Fail("alg not supported");
        }

        if (!h.TryGetProperty("jwk", out var jwk) || jwk.ValueKind != JsonValueKind.Object)
        {
            return Fail("jwk missing");
        }

        if (PrivateMembers.Any(m => jwk.TryGetProperty(m, out _)))
        {
            return Fail("jwk has a private member");
        }

        var key = PublicJwk.Read(jwk, alg);
        if (key is null)
        {
            return Fail("jwk is not a valid key for alg");
        }

        using var payload = Jws.DecodeJson(parts[1]);
        if (payload?.RootElement is not { ValueKind: JsonValueKind.Object } p)
        {
            return Fail("payload is not a JSON object");
        }

        var claims = CheckClaims(p, request);
        if (!claims.IsSuccess)
        {
            return Result.Failure<DpopProof>(claims.Error);
        }

        var signature = Jws.Decode(parts[2]);
        if (signature is null || !key.Verify(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature))
        {
            return Fail("signature does not verify");
        }

        return Result.Success(new DpopProof(key.Thumbprint, claims.Value.Jti, claims.Value.IssuedAt));
    }

    private Result<(string Jti, DateTimeOffset IssuedAt)> CheckClaims(JsonElement payload, DpopRequest request)
    {
        if (!Jws.IsString(payload, "jti", out var jti) || jti.Length > MaxJtiLength)
        {
            return ClaimFail("jti missing or too long");
        }

        // RFC 9110: the method is case-sensitive.
        if (!Jws.IsString(payload, "htm", out var htm) || !string.Equals(htm, request.Method, StringComparison.Ordinal))
        {
            return ClaimFail("htm does not match the method");
        }

        if (!Jws.IsString(payload, "htu", out var htu) || !SameEndpoint(htu, request.Url))
        {
            return ClaimFail("htu does not match the endpoint");
        }

        if (!payload.TryGetProperty("iat", out var iatElement)
            || iatElement.ValueKind != JsonValueKind.Number
            || !iatElement.TryGetDouble(out var iatSeconds)
            || !double.IsFinite(iatSeconds))
        {
            return ClaimFail("iat missing");
        }

        // Plain seconds: a TimeSpan built from a far iat would overflow and throw.
        var nowSeconds = _time.GetUtcNow().ToUnixTimeMilliseconds() / 1000.0;
        if (Math.Abs(nowSeconds - iatSeconds) > MaxClockDifference.TotalSeconds)
        {
            return ClaimFail("iat outside the window");
        }

        if (request.AccessToken is { } accessToken)
        {
            var expected = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            if (!Jws.IsString(payload, "ath", out var ath) || !string.Equals(ath, expected, StringComparison.Ordinal))
            {
                return ClaimFail("ath does not match the access token");
            }
        }

        return Result.Success((jti, DateTimeOffset.UnixEpoch.AddSeconds(Math.Floor(iatSeconds))));
    }

    /// <summary>
    /// RFC 9449, section 4.3: <c>htu</c> matches the request URI without query and fragment. Both sides are normalized
    /// (RFC 3986, section 6): scheme and host compare without case, a default port drops out. The path compares exactly.
    /// </summary>
    private static bool SameEndpoint(string htu, Uri endpoint)
    {
        if (!Uri.TryCreate(htu, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            return false;
        }

        const UriComponents Parts = UriComponents.SchemeAndServer | UriComponents.Path;
        return string.Equals(
            uri.GetComponents(Parts, UriFormat.UriEscaped),
            endpoint.GetComponents(Parts, UriFormat.UriEscaped),
            StringComparison.Ordinal);
    }

    // RFC 7515, section 4.1.9: "application/" may be left out, and the comparison ignores case.
    private static bool IsDpopType(JsonElement header) =>
        Jws.IsString(header, "typ", out var typ)
        && (typ.Equals("dpop+jwt", StringComparison.OrdinalIgnoreCase) || typ.Equals("application/dpop+jwt", StringComparison.OrdinalIgnoreCase));

    private static Result<DpopProof> Fail(string reason) => Result.Failure<DpopProof>(OAuthError.InvalidDpopProof(reason));

    private static Result<(string Jti, DateTimeOffset IssuedAt)> ClaimFail(string reason) =>
        Result.Failure<(string Jti, DateTimeOffset IssuedAt)>(OAuthError.InvalidDpopProof(reason));
}
