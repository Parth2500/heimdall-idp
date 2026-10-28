using System.Text;
using System.Text.Json;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;
using Heimdall.Infrastructure.Keys;

namespace Heimdall.Infrastructure.Clients;

/// <summary>
/// Checks a <c>private_key_jwt</c> client assertion (RFC 7523, section 3) by the rules of D48. The cheap checks run
/// first: size, format, header, and claims. The signature check runs last, and nothing here reads the database.
/// </summary>
/// <remarks>
/// The key is the registered key that the header's <c>kid</c> names (D46). The algorithm comes from
/// <see cref="SupportedAlgorithms"/>, and it must match the key type and the key's own <c>alg</c>, when it has one.
/// </remarks>
internal sealed class ClientAssertionValidator : IClientAssertionValidator
{
    /// <summary>The values of <c>token_endpoint_auth_signing_alg_values_supported</c> in discovery.</summary>
    public static readonly IReadOnlyList<string> SupportedAlgorithms = ClientAssertionTypes.SupportedAlgorithms;

    // An assertion with an RSA-4096 signature is under 2 KB. The limit stops a large value before any decoding.
    private const int MaxAssertionLength = 4096;
    private const int MaxJtiLength = 256;

    private readonly TimeProvider _time;

    public ClientAssertionValidator(TimeProvider time)
    {
        _time = time;
    }

    public string? ReadClientId(string assertion)
    {
        if (string.IsNullOrEmpty(assertion) || assertion.Length > MaxAssertionLength)
        {
            return null;
        }

        var parts = assertion.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        using var payload = Jws.DecodeJson(parts[1]);
        // Jws.IsString refuses an empty string.
        return payload?.RootElement is { ValueKind: JsonValueKind.Object } p && Jws.IsString(p, "sub", out var sub) ? sub : null;
    }

    public Result<ClientAssertion> Validate(string assertion, Client client, string issuer)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(issuer);

        if (client.Jwks is null)
        {
            return Fail("client has no registered keys");
        }

        if (string.IsNullOrEmpty(assertion) || assertion.Length > MaxAssertionLength)
        {
            return Fail("assertion missing or too long");
        }

        var parts = assertion.Split('.');
        if (parts.Length != 3)
        {
            return Fail("assertion is not a compact JWS");
        }

        using var header = Jws.DecodeJson(parts[0]);
        if (header?.RootElement is not { ValueKind: JsonValueKind.Object } h)
        {
            return Fail("header is not a JSON object");
        }

        if (h.TryGetProperty("crit", out _))
        {
            return Fail("crit header");
        }

        if (!Jws.IsString(h, "alg", out var alg) || !SupportedAlgorithms.Contains(alg, StringComparer.Ordinal))
        {
            return Fail("alg not supported");
        }

        if (!IsAssertionType(h))
        {
            return Fail("typ is another kind of JWT");
        }

        if (!Jws.IsString(h, "kid", out var kid))
        {
            return Fail("kid missing");
        }

        var key = FindKey(client.Jwks, kid, alg);
        if (key is null)
        {
            return Fail("kid unknown or key not valid for alg");
        }

        using var payload = Jws.DecodeJson(parts[1]);
        if (payload?.RootElement is not { ValueKind: JsonValueKind.Object } p)
        {
            return Fail("payload is not a JSON object");
        }

        var claims = CheckClaims(p, client.ClientId, issuer);
        if (!claims.IsSuccess)
        {
            return claims;
        }

        var signature = Jws.Decode(parts[2]);
        if (signature is null || !key.Verify(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature))
        {
            return Fail("signature does not verify");
        }

        return claims;
    }

    private Result<ClientAssertion> CheckClaims(JsonElement payload, string clientId, string issuer)
    {
        // RFC 7523, section 3: iss and sub are the client_id for client authentication.
        if (!Jws.IsString(payload, "iss", out var iss) || !string.Equals(iss, clientId, StringComparison.Ordinal))
        {
            return Fail("iss is not the client_id");
        }

        if (!Jws.IsString(payload, "sub", out var sub) || !string.Equals(sub, clientId, StringComparison.Ordinal))
        {
            return Fail("sub is not the client_id");
        }

        // D48: aud is exactly the issuer, as one string (draft-ietf-oauth-rfc7523bis). An array or an endpoint URL fails,
        // so an assertion made for another server, or for one endpoint, cannot work here.
        if (!Jws.IsString(payload, "aud", out var aud) || !string.Equals(aud, issuer, StringComparison.Ordinal))
        {
            return Fail("aud is not the issuer");
        }

        if (!Jws.IsString(payload, "jti", out var jti) || jti.Length > MaxJtiLength)
        {
            return Fail("jti missing or too long");
        }

        // Plain seconds: a TimeSpan built from a far value would overflow and throw.
        var now = _time.GetUtcNow().ToUnixTimeMilliseconds() / 1000.0;
        var skew = ClientAssertionTypes.MaxClockDifference.TotalSeconds;
        if (!TryReadSeconds(payload, "exp", out var exp))
        {
            return Fail("exp missing");
        }

        if (exp <= now - skew)
        {
            return Fail("expired");
        }

        // A long-lived assertion is a reusable credential. D48 limits it, so the replay store stays small too.
        if (exp > now + ClientAssertionTypes.MaxLifetime.TotalSeconds + skew)
        {
            return Fail("exp too far in the future");
        }

        foreach (var name in (string[])["iat", "nbf"])
        {
            if (payload.TryGetProperty(name, out _) && (!TryReadSeconds(payload, name, out var value) || value > now + skew))
            {
                return Fail(name + " in the future or not a number");
            }
        }

        return Result.Success(new ClientAssertion(jti, DateTimeOffset.UnixEpoch.AddSeconds(Math.Ceiling(exp))));
    }

    /// <summary>The registered key with this <c>kid</c>, as a key for <paramref name="alg"/>, or null.</summary>
    private static PublicJwk? FindKey(string jwks, string kid, string alg)
    {
        using var document = JsonDocument.Parse(jwks);
        foreach (var key in document.RootElement.GetProperty("keys").EnumerateArray())
        {
            if (!Jws.IsString(key, "kid", out var keyId) || !string.Equals(keyId, kid, StringComparison.Ordinal))
            {
                continue;
            }

            // RFC 7517, section 4.4: a key that names its algorithm is for that algorithm only.
            if (key.TryGetProperty("alg", out _) && (!Jws.IsString(key, "alg", out var keyAlg) || keyAlg != alg))
            {
                return null;
            }

            return PublicJwk.Read(key, alg);
        }

        return null;
    }

    // draft-ietf-oauth-rfc7523bis: "client-authentication+jwt". Older clients send "JWT" or nothing. Any other type is a
    // JWT made for something else, such as a DPoP proof or an access token.
    private static bool IsAssertionType(JsonElement header)
    {
        if (!header.TryGetProperty("typ", out _))
        {
            return true;
        }

        return Jws.IsString(header, "typ", out var typ)
            && (typ.Equals("JWT", StringComparison.OrdinalIgnoreCase)
                || typ.Equals("client-authentication+jwt", StringComparison.OrdinalIgnoreCase)
                || typ.Equals("application/client-authentication+jwt", StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryReadSeconds(JsonElement payload, string name, out double seconds)
    {
        seconds = 0;
        return payload.TryGetProperty(name, out var element)
            && element.ValueKind == JsonValueKind.Number
            && element.TryGetDouble(out seconds)
            && double.IsFinite(seconds);
    }

    private static Result<ClientAssertion> Fail(string reason) => Result.Failure<ClientAssertion>(OAuthError.InvalidClient(reason));
}
