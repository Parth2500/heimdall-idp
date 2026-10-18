using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Domain.Keys;

namespace Heimdall.Application.Keys;

/// <summary>
/// The public half of an RSA signing key, as a JWK (RFC 7517). The type has no private field, so the JWKS
/// cannot serialize one by mistake (threat model, JWKS, Tampering).
/// </summary>
public sealed record RsaPublicJwk
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    [JsonConstructor]
    public RsaPublicJwk(string kid, string n, string e)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);
        ArgumentException.ThrowIfNullOrWhiteSpace(n);
        ArgumentException.ThrowIfNullOrWhiteSpace(e);
        Kid = kid;
        N = n;
        E = e;
    }

    [JsonPropertyName("kty")]
    public string Kty { get; } = "RSA";

    [JsonPropertyName("use")]
    public string Use { get; } = "sig";

    [JsonPropertyName("alg")]
    public string Alg { get; } = SigningKey.Algorithm;

    [JsonPropertyName("kid")]
    public string Kid { get; }

    [JsonPropertyName("n")]
    public string N { get; }

    [JsonPropertyName("e")]
    public string E { get; }

    /// <summary>Creates the JWK. The <c>kid</c> is the RFC 7638 thumbprint of the public key.</summary>
    public static RsaPublicJwk FromPublicParameters(string n, string e) => new(ComputeThumbprint(n, e), n, e);

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static RsaPublicJwk FromJson(string json) =>
        JsonSerializer.Deserialize<RsaPublicJwk>(json, JsonOptions)
        ?? throw new JsonException("The public JWK is empty.");

    /// <summary>
    /// RFC 7638: SHA-256 over the required members in lexicographic order, with no white space.
    /// The thumbprint is stable and shows no internal identifier.
    /// </summary>
    public static string ComputeThumbprint(string n, string e)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(n);
        ArgumentException.ThrowIfNullOrWhiteSpace(e);

        // n and e are base64url, so they need no JSON escaping.
        var canonical = $$"""{"e":"{{e}}","kty":"RSA","n":"{{n}}"}""";
        return Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
