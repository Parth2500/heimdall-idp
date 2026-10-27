using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CsCheck;
using Heimdall.Application.Dpop;
using Heimdall.Infrastructure.Dpop;
using Heimdall.UnitTests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Properties;

public sealed class DpopProofValidatorProperties : IDisposable
{
    private const string Endpoint = "https://acme.example.com/oauth/v1/token";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly DpopRequest Request = new("POST", new Uri(Endpoint));

    private readonly DpopProofValidator _validator = new(new FakeTimeProvider(Now));
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose() => _key.Dispose();

    private static readonly Gen<JsonNode?> Value = Gen.OneOf<JsonNode?>(
        Gen.Const<JsonNode?>((JsonNode?)null),
        Gen.Bool.Select(b => (JsonNode?)JsonValue.Create(b)),
        Gen.Long.Select(n => (JsonNode?)JsonValue.Create(n)),
        Generators.UnicodeText.Select(s => (JsonNode?)JsonValue.Create(s)),
        Generators.UnicodeText.Select(s => (JsonNode?)new JsonArray(JsonValue.Create(s))));

    private JsonObject Header() => new() { ["typ"] = "dpop+jwt", ["alg"] = "ES256", ["jwk"] = TestDpop.EcJwk(_key) };

    private static JsonObject Payload() => new() { ["jti"] = "j", ["htm"] = "POST", ["htu"] = Endpoint, ["iat"] = Now.ToUnixTimeSeconds() };

    [Fact]
    public void Any_text_is_refused_without_an_exception()
    {
        Generators.TokenLike.Sample(proof => Assert.False(_validator.Validate(proof, Request).IsSuccess), iter: 10_000);
    }

    [Fact]
    public void Signed_proofs_with_any_header_or_claim_values_never_throw()
    {
        var member = Gen.OneOf("typ", "alg", "jwk", "crit", "kty", "crv", "x", "y", "n", "e", "jti", "htm", "htu", "iat", "ath");

        Gen.Select(member, Value, Gen.Bool).Sample((name, value, inHeader) =>
        {
            var header = Header();
            var payload = Payload();
            if (name is "kty" or "crv" or "x" or "y" or "n" or "e")
            {
                ((JsonObject)header["jwk"]!)[name] = value?.DeepClone();
            }
            else
            {
                (inHeader ? header : payload)[name] = value?.DeepClone();
            }

            // The result can be either; only an exception fails.
            _ = _validator.Validate(TestDpop.Sign(header, payload, _key), Request);
        }, iter: 2_000);
    }

    [Fact]
    public void Changing_any_one_character_of_a_valid_proof_makes_it_invalid()
    {
        var proof = TestDpop.Sign(Header(), Payload(), _key);
        Assert.True(_validator.Validate(proof, Request).IsSuccess);

        Gen.Select(Gen.Int[0, proof.Length - 1], Gen.Char[Generators.Base64UrlChars + ".=+/ "])
            .Where((i, c) => proof[i] != c)
            .Sample((index, replacement) =>
            {
                var changed = string.Concat(proof.AsSpan(0, index), replacement.ToString(), proof.AsSpan(index + 1));

                Assert.False(_validator.Validate(changed, Request).IsSuccess);
            }, iter: 3_000);
    }

    [Fact]
    public void Random_EC_points_never_throw()
    {
        // Most random coordinates are not on the curve. The key import must refuse them quietly.
        Gen.Select(Gen.Byte.Array[32], Gen.Byte.Array[32]).Sample((x, y) =>
        {
            var header = Header();
            var jwk = (JsonObject)header["jwk"]!;
            jwk["x"] = Base64Url.EncodeToString(x);
            jwk["y"] = Base64Url.EncodeToString(y);

            Assert.False(_validator.Validate(TestDpop.Sign(header, Payload(), _key), Request).IsSuccess);
        }, iter: 1_000);
    }

    [Fact]
    public void Any_htu_matches_only_the_same_endpoint()
    {
        var host = Gen.OneOf("acme.example.com", "ACME.example.com", "other.example.com");
        var path = Gen.OneOf("/oauth/v1/token", "/oauth/v1/token/", "/oauth/v1/Token", "/oauth/v1/revoke");
        var suffix = Gen.OneOf("", "?a=1", "#f", ":443", ":8443");

        Gen.Select(Gen.OneOf("https", "http"), host, path, suffix).Sample((scheme, h, p, s) =>
        {
            var htu = s.StartsWith(':') ? $"{scheme}://{h}{s}{p}" : $"{scheme}://{h}{p}{s}";
            var payload = Payload();
            payload["htu"] = htu;

            var expected = scheme == "https"
                && h.Equals("acme.example.com", StringComparison.OrdinalIgnoreCase)
                && p == "/oauth/v1/token"
                && s != ":8443";
            Assert.Equal(expected, _validator.Validate(TestDpop.Sign(Header(), payload, _key), Request).IsSuccess);
        }, iter: 500);
    }
}
