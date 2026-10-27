using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Heimdall.IntegrationTests.Api;

/// <summary>A client's DPoP key (P-256, ES256) that signs real proofs (RFC 9449, section 4.2).</summary>
internal sealed class ClientKey : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public JsonObject Jwk
    {
        get
        {
            var p = _key.ExportParameters(includePrivateParameters: false);
            return new JsonObject
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = Base64Url.EncodeToString(p.Q.X!),
                ["y"] = Base64Url.EncodeToString(p.Q.Y!),
            };
        }
    }

    /// <summary>The RFC 7638 thumbprint: SHA-256 over the required members in lexical order.</summary>
    public string Thumbprint
    {
        get
        {
            var jwk = Jwk;
            var canonical = $$"""{"crv":"P-256","kty":"EC","x":"{{jwk["x"]}}","y":"{{jwk["y"]}}"}""";
            return Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        }
    }

    /// <param name="accessToken">At a resource, the token that the proof goes with. Its hash becomes <c>ath</c>.</param>
    public string Proof(string htu, DateTimeOffset iat, string? jti = null, string htm = "POST", string? accessToken = null)
    {
        var header = new JsonObject { ["typ"] = "dpop+jwt", ["alg"] = "ES256", ["jwk"] = Jwk };
        var payload = new JsonObject
        {
            ["jti"] = jti ?? Guid.NewGuid().ToString("N"),
            ["htm"] = htm,
            ["htu"] = htu,
            ["iat"] = iat.ToUnixTimeSeconds(),
        };
        if (accessToken is not null)
        {
            payload["ath"] = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }

        var input = Encode(header) + "." + Encode(payload);
        var signature = _key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return input + "." + Base64Url.EncodeToString(signature);
    }

    public void Dispose() => _key.Dispose();

    private static string Encode(JsonNode node) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(node.ToJsonString()));
}
