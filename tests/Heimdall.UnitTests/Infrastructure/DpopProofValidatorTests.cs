using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.Keys;
using Heimdall.Infrastructure.Dpop;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Infrastructure;

/// <summary>Builds DPoP proofs as a client does, for the validator tests.</summary>
internal static class TestDpop
{
    public static JsonObject EcJwk(ECDsa key)
    {
        var p = key.ExportParameters(includePrivateParameters: false);
        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64Url.EncodeToString(p.Q.X!),
            ["y"] = Base64Url.EncodeToString(p.Q.Y!),
        };
    }

    public static JsonObject RsaJwk(RSA key)
    {
        var p = key.ExportParameters(includePrivateParameters: false);
        return new JsonObject { ["kty"] = "RSA", ["n"] = Base64Url.EncodeToString(p.Modulus!), ["e"] = Base64Url.EncodeToString(p.Exponent!) };
    }

    public static string Sign(JsonNode header, JsonNode payload, AsymmetricAlgorithm key)
    {
        var input = TestJwt.Encode(header) + "." + TestJwt.Encode(payload);
        var data = Encoding.ASCII.GetBytes(input);
        var signature = key switch
        {
            ECDsa ec => ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            RSA rsa => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentException("Unknown key type.", nameof(key)),
        };
        return input + "." + Base64Url.EncodeToString(signature);
    }
}

public sealed class DpopProofValidatorTests : IDisposable
{
    private const string TokenEndpoint = "https://acme.example.com/oauth/v1/token";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly DpopProofValidator _validator;
    private readonly ECDsa _ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _otherEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly RSA _rsa = RSA.Create(2048);

    public DpopProofValidatorTests()
    {
        _validator = new DpopProofValidator(_time);
    }

    public void Dispose()
    {
        _ec.Dispose();
        _otherEc.Dispose();
        _rsa.Dispose();
    }

    private JsonObject Header(string alg = "ES256", JsonObject? jwk = null) =>
        new() { ["typ"] = "dpop+jwt", ["alg"] = alg, ["jwk"] = jwk ?? TestDpop.EcJwk(_ec) };

    private static JsonObject Payload(string htm = "POST", string htu = TokenEndpoint, long? iat = null, string jti = "jti-1") => new()
    {
        ["jti"] = jti,
        ["htm"] = htm,
        ["htu"] = htu,
        ["iat"] = iat ?? Now.ToUnixTimeSeconds(),
    };

    private static JsonObject With(JsonObject node, string name, JsonNode? value)
    {
        node[name] = value;
        return node;
    }

    private static JsonObject Without(JsonObject node, string name)
    {
        node.Remove(name);
        return node;
    }

    private Result<DpopProof> Validate(string proof, string method = "POST", string url = TokenEndpoint, string? accessToken = null) =>
        _validator.Validate(proof, new DpopRequest(method, new Uri(url), accessToken));

    private Result<DpopProof> ValidateEc(JsonObject header, JsonObject payload, AsymmetricAlgorithm? key = null) =>
        Validate(TestDpop.Sign(header, payload, key ?? _ec));

    private static void AssertRefused(Result<DpopProof> result, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(OAuthError.InvalidDpopProofCode, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
    }

    [Fact]
    public void Thumbprint_matches_the_RFC_9449_example()
    {
        // RFC 9449, section 6.1: the example key and its jkt.
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["x"] = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            ["y"] = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
            ["crv"] = "P-256",
        };

        // The example's private key is not published, so only the thumbprint is checked: a valid proof cannot be made.
        // The validator reads the key and computes the thumbprint before the signature check, so a signature failure
        // here proves that the key passed every other rule.
        var proof = TestJwt.Encode(Header(jwk: jwk)) + "." + TestJwt.Encode(Payload()) + "." + new string('A', 86);
        AssertRefused(Validate(proof), "signature does not verify");
        Assert.Equal("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", DpopThumbprint(jwk));
    }

    private static string DpopThumbprint(JsonObject ecJwk) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $$"""{"crv":"{{ecJwk["crv"]}}","kty":"EC","x":"{{ecJwk["x"]}}","y":"{{ecJwk["y"]}}"}""")));

    [Fact]
    public void Valid_ES256_proof_gives_the_key_thumbprint_jti_and_iat()
    {
        var result = ValidateEc(Header(), Payload(iat: Now.ToUnixTimeSeconds() - 10));

        Assert.True(result.IsSuccess);
        Assert.Equal(DpopThumbprint(TestDpop.EcJwk(_ec)), result.Value.KeyThumbprint);
        Assert.Equal("jti-1", result.Value.Jti);
        Assert.Equal(Now.AddSeconds(-10), result.Value.IssuedAt);
    }

    [Fact]
    public void Valid_RS256_proof_gives_the_RFC_7638_thumbprint()
    {
        var jwk = TestDpop.RsaJwk(_rsa);

        var result = Validate(TestDpop.Sign(Header("RS256", jwk), Payload(), _rsa));

        Assert.True(result.IsSuccess);
        Assert.Equal(RsaPublicJwk.ComputeThumbprint(jwk["n"]!.ToString(), jwk["e"]!.ToString()), result.Value.KeyThumbprint);
    }

    [Fact]
    public void Two_keys_give_two_thumbprints()
    {
        var first = ValidateEc(Header(), Payload());
        var second = ValidateEc(Header(jwk: TestDpop.EcJwk(_otherEc)), Payload(), _otherEc);

        Assert.NotEqual(first.Value.KeyThumbprint, second.Value.KeyThumbprint);
    }

    [Theory]
    [InlineData("dpop+jwt")]
    [InlineData("application/dpop+jwt")]
    [InlineData("DPoP+JWT")]
    public void Typ_values_of_RFC_9449_are_accepted(string typ)
    {
        Assert.True(ValidateEc(With(Header(), "typ", typ), Payload()).IsSuccess);
    }

    [Theory]
    [InlineData("JWT")]
    [InlineData("at+jwt")]
    [InlineData("dpop+jwt ")]
    public void Other_typ_values_are_refused(string typ)
    {
        AssertRefused(ValidateEc(With(Header(), "typ", typ), Payload()), "typ is not dpop+jwt");
    }

    [Fact]
    public void Missing_typ_is_refused()
    {
        AssertRefused(ValidateEc(Without(Header(), "typ"), Payload()), "typ is not dpop+jwt");
    }

    [Fact]
    public void Crit_header_is_refused()
    {
        AssertRefused(ValidateEc(With(Header(), "crit", new JsonArray("exp")), Payload()), "crit header");
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES384")]
    [InlineData("PS256")]
    [InlineData("RS512")]
    [InlineData("es256")]
    public void Algorithms_outside_the_list_are_refused(string alg)
    {
        AssertRefused(ValidateEc(Header(alg), Payload()), "alg not supported");
    }

    [Fact]
    public void Missing_alg_is_refused()
    {
        AssertRefused(ValidateEc(Without(Header(), "alg"), Payload()), "alg not supported");
    }

    [Fact]
    public void ES256_with_an_RSA_key_is_refused()
    {
        AssertRefused(ValidateEc(Header("ES256", TestDpop.RsaJwk(_rsa)), Payload(), _rsa), "jwk is not a valid key for alg");
    }

    [Fact]
    public void RS256_with_an_EC_key_is_refused()
    {
        AssertRefused(ValidateEc(Header("RS256"), Payload()), "jwk is not a valid key for alg");
    }

    [Fact]
    public void Missing_jwk_is_refused()
    {
        AssertRefused(ValidateEc(Without(Header(), "jwk"), Payload()), "jwk missing");
    }

    [Fact]
    public void Jwk_that_is_not_an_object_is_refused()
    {
        AssertRefused(ValidateEc(With(Header(), "jwk", "key"), Payload()), "jwk missing");
    }

    [Theory]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("qi")]
    [InlineData("oth")]
    [InlineData("k")]
    public void Jwk_with_a_private_member_is_refused(string member)
    {
        var jwk = With(TestDpop.EcJwk(_ec), member, "AAAA");

        AssertRefused(ValidateEc(Header(jwk: jwk), Payload()), "jwk has a private member");
    }

    [Theory]
    [InlineData("crv", "P-384")]
    [InlineData("kty", "OKP")]
    [InlineData("x", "AAAA")]
    [InlineData("y", "AAAA")]
    [InlineData("x", "not base64url!")]
    public void EC_key_that_is_not_P256_is_refused(string member, string value)
    {
        AssertRefused(ValidateEc(Header(jwk: With(TestDpop.EcJwk(_ec), member, value)), Payload()), "jwk is not a valid key for alg");
    }

    [Theory]
    [InlineData("crv")]
    [InlineData("x")]
    [InlineData("y")]
    [InlineData("kty")]
    public void EC_key_with_a_missing_member_is_refused(string member)
    {
        AssertRefused(ValidateEc(Header(jwk: Without(TestDpop.EcJwk(_ec), member)), Payload()), "jwk is not a valid key for alg");
    }

    [Fact]
    public void EC_point_that_is_not_on_the_curve_is_refused()
    {
        var jwk = TestDpop.EcJwk(_ec);
        jwk["y"] = Base64Url.EncodeToString(new byte[32]);

        AssertRefused(ValidateEc(Header(jwk: jwk), Payload()), "signature does not verify");
    }

    [Fact]
    public void RSA_key_under_2048_bits_is_refused()
    {
        using var weak = RSA.Create(1024);

        AssertRefused(Validate(TestDpop.Sign(Header("RS256", TestDpop.RsaJwk(weak)), Payload(), weak)), "jwk is not a valid key for alg");
    }

    [Fact]
    public void RSA_key_over_4096_bits_is_refused()
    {
        var jwk = TestDpop.RsaJwk(_rsa);
        jwk["n"] = Base64Url.EncodeToString(Enumerable.Repeat((byte)0xC3, 513).ToArray());

        AssertRefused(Validate(TestDpop.Sign(Header("RS256", jwk), Payload(), _rsa)), "jwk is not a valid key for alg");
    }

    [Fact]
    public void RSA_modulus_with_a_leading_zero_is_refused()
    {
        // The same key with a leading zero octet would have a second thumbprint.
        var jwk = TestDpop.RsaJwk(_rsa);
        jwk["n"] = Base64Url.EncodeToString([0, .. Base64Url.DecodeFromChars(jwk["n"]!.ToString())]);

        AssertRefused(Validate(TestDpop.Sign(Header("RS256", jwk), Payload(), _rsa)), "jwk is not a valid key for alg");
    }

    [Theory]
    [InlineData("n")]
    [InlineData("e")]
    [InlineData("kty")]
    public void RSA_key_with_a_missing_member_is_refused(string member)
    {
        AssertRefused(
            Validate(TestDpop.Sign(Header("RS256", Without(TestDpop.RsaJwk(_rsa), member)), Payload(), _rsa)),
            "jwk is not a valid key for alg");
    }

    [Fact]
    public void Signature_of_another_key_is_refused()
    {
        AssertRefused(ValidateEc(Header(), Payload(), _otherEc), "signature does not verify");
    }

    [Fact]
    public void Changed_payload_is_refused()
    {
        var parts = TestDpop.Sign(Header(), Payload(), _ec).Split('.');
        var changed = TestJwt.Encode(Payload(jti: "jti-2"));

        AssertRefused(Validate(parts[0] + "." + changed + "." + parts[2]), "signature does not verify");
    }

    [Fact]
    public void Empty_or_malformed_signature_is_refused()
    {
        var parts = TestDpop.Sign(Header(), Payload(), _ec).Split('.');

        AssertRefused(Validate(parts[0] + "." + parts[1] + "."), "signature does not verify");
        AssertRefused(Validate(parts[0] + "." + parts[1] + ".AB"), "signature does not verify");
    }

    [Theory]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    public void Wrong_number_of_parts_is_refused(string proof)
    {
        AssertRefused(Validate(proof), proof.Length == 0 ? "proof missing or too long" : "proof is not a compact JWS");
    }

    [Fact]
    public void Proof_of_exactly_4096_characters_is_checked()
    {
        // An ES256 signature is always 86 characters. Base64url text never has a length of 1 mod 4, so a payload filler
        // alone cannot reach every total. A short header filler moves the header length too.
        var proof = (
                from headerPad in Enumerable.Range(0, 4)
                from n in Enumerable.Range(2700, 400)
                select TestDpop.Sign(With(Header(), "p", new string('h', headerPad)), With(Payload(), "pad", new string('x', n)), _ec))
            .First(p => p.Length == 4096);

        Assert.True(Validate(proof).IsSuccess);
    }

    [Fact]
    public void RSA_key_of_4096_bits_is_accepted()
    {
        using var strong = RSA.Create(4096);

        Assert.True(Validate(TestDpop.Sign(Header("RS256", TestDpop.RsaJwk(strong)), Payload(), strong)).IsSuccess);
    }

    [Fact]
    public void RSA_key_that_cannot_be_imported_is_refused()
    {
        // An exponent of zero: the key import fails, and the validator refuses the proof without an exception.
        var jwk = TestDpop.RsaJwk(_rsa);
        jwk["e"] = Base64Url.EncodeToString([0]);

        AssertRefused(Validate(TestDpop.Sign(Header("RS256", jwk), Payload(), _rsa)), "signature does not verify");
    }

    [Fact]
    public void Proof_over_4096_characters_is_refused()
    {
        var proof = TestDpop.Sign(Header(), With(Payload(), "pad", new string('x', 4000)), _ec);

        Assert.True(proof.Length > 4096);
        AssertRefused(Validate(proof), "proof missing or too long");
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[1]")]
    public void Header_that_is_not_a_json_object_is_refused(string header)
    {
        var proof = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header)) + "." + TestJwt.Encode(Payload()) + ".sig";

        AssertRefused(Validate(proof), "header is not a JSON object");
    }

    [Fact]
    public void Payload_that_is_not_a_json_object_is_refused()
    {
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("[1]"));

        AssertRefused(Validate(TestJwt.Encode(Header()) + "." + payload + ".sig"), "payload is not a JSON object");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Missing_jti_is_refused(string? jti)
    {
        var payload = jti is null ? Without(Payload(), "jti") : Payload(jti: jti);

        AssertRefused(ValidateEc(Header(), payload), "jti missing or too long");
    }

    [Fact]
    public void Jti_of_256_characters_is_accepted_and_257_is_refused()
    {
        Assert.True(ValidateEc(Header(), Payload(jti: new string('j', 256))).IsSuccess);
        AssertRefused(ValidateEc(Header(), Payload(jti: new string('j', 257))), "jti missing or too long");
    }

    [Theory]
    [InlineData("post")]
    [InlineData("GET")]
    public void Htm_that_differs_from_the_method_is_refused(string htm)
    {
        AssertRefused(ValidateEc(Header(), Payload(htm: htm)), "htm does not match the method");
    }

    [Fact]
    public void Missing_htm_is_refused()
    {
        AssertRefused(ValidateEc(Header(), Without(Payload(), "htm")), "htm does not match the method");
    }

    [Theory]
    [InlineData("https://acme.example.com/oauth/v1/token?x=1")]
    [InlineData("https://acme.example.com/oauth/v1/token#f")]
    [InlineData("https://ACME.example.com/oauth/v1/token")]
    [InlineData("HTTPS://acme.example.com/oauth/v1/token")]
    [InlineData("https://acme.example.com:443/oauth/v1/token")]
    public void Htu_matches_without_query_fragment_case_of_host_or_default_port(string htu)
    {
        Assert.True(ValidateEc(Header(), Payload(htu: htu)).IsSuccess);
    }

    [Theory]
    [InlineData("https://acme.example.com/oauth/v1/token/")]
    [InlineData("https://acme.example.com/oauth/v1/TOKEN")]
    [InlineData("https://acme.example.com/oauth/v1/revoke")]
    [InlineData("http://acme.example.com/oauth/v1/token")]
    [InlineData("https://other.example.com/oauth/v1/token")]
    [InlineData("https://acme.example.com:8443/oauth/v1/token")]
    [InlineData("https://user@acme.example.com/oauth/v1/token")]
    [InlineData("/oauth/v1/token")]
    public void Htu_for_another_endpoint_is_refused(string htu)
    {
        AssertRefused(ValidateEc(Header(), Payload(htu: htu)), "htu does not match the endpoint");
    }

    [Fact]
    public void Missing_htu_is_refused()
    {
        AssertRefused(ValidateEc(Header(), Without(Payload(), "htu")), "htu does not match the endpoint");
    }

    [Theory]
    [InlineData(-60)]
    [InlineData(60)]
    [InlineData(0)]
    public void Iat_within_60_seconds_is_accepted(int offset)
    {
        Assert.True(ValidateEc(Header(), Payload(iat: Now.ToUnixTimeSeconds() + offset)).IsSuccess);
    }

    [Theory]
    [InlineData(-61)]
    [InlineData(61)]
    [InlineData(-86_400)]
    public void Iat_outside_60_seconds_is_refused(int offset)
    {
        AssertRefused(ValidateEc(Header(), Payload(iat: Now.ToUnixTimeSeconds() + offset)), "iat outside the window");
    }

    [Theory]
    [InlineData(10_271_280_623_422L)] // Found by the property tests: TimeSpan.FromSeconds overflowed and threw.
    [InlineData(-7_352_485_113_620_914L)]
    [InlineData(long.MaxValue)]
    public void Far_iat_is_refused_without_an_exception(long iat)
    {
        AssertRefused(ValidateEc(Header(), Payload(iat: iat)), "iat outside the window");
    }

    [Fact]
    public void Fractional_iat_is_accepted()
    {
        var result = ValidateEc(Header(), With(Payload(), "iat", Now.ToUnixTimeSeconds() - 1.5));

        Assert.True(result.IsSuccess);
        Assert.Equal(Now.AddSeconds(-2), result.Value.IssuedAt);
    }

    [Fact]
    public void Iat_that_is_not_a_number_is_refused()
    {
        AssertRefused(ValidateEc(Header(), With(Payload(), "iat", Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))), "iat missing");
        AssertRefused(ValidateEc(Header(), Without(Payload(), "iat")), "iat missing");
    }

    [Fact]
    public void Ath_must_hash_the_access_token_at_a_resource()
    {
        const string AccessToken = "header.payload.signature";
        var ath = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(AccessToken)));
        const string UserInfo = "https://acme.example.com/oauth/v1/userinfo";
        var payload = With(Payload("GET", UserInfo), "ath", ath);

        Assert.True(Validate(TestDpop.Sign(Header(), payload, _ec), "GET", UserInfo, AccessToken).IsSuccess);
        AssertRefused(Validate(TestDpop.Sign(Header(), payload, _ec), "GET", UserInfo, "other.access.token"), "ath does not match the access token");
        AssertRefused(Validate(TestDpop.Sign(Header(), Payload("GET", UserInfo), _ec), "GET", UserInfo, AccessToken), "ath does not match the access token");
    }

    [Fact]
    public void Ath_is_not_needed_at_the_token_endpoint()
    {
        Assert.True(ValidateEc(Header(), With(Payload(), "ath", "anything")).IsSuccess);
    }
}
