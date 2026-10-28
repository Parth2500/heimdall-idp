using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Domain.Clients;
using Heimdall.Infrastructure.Clients;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Infrastructure;

/// <summary>Builds client assertions as a client library does, for the validator tests (D48).</summary>
internal static class TestAssertion
{
    public static string Sign(JsonNode header, JsonNode payload, AsymmetricAlgorithm key, RSASignaturePadding? padding = null)
    {
        var input = TestJwt.Encode(header) + "." + TestJwt.Encode(payload);
        var data = Encoding.ASCII.GetBytes(input);
        var signature = key switch
        {
            ECDsa ec => ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            RSA rsa => rsa.SignData(data, HashAlgorithmName.SHA256, padding ?? RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentException("Unknown key type.", nameof(key)),
        };
        return input + "." + Base64Url.EncodeToString(signature);
    }
}

public sealed class ClientAssertionValidatorTests : IDisposable
{
    private const string Issuer = "https://acme.example.com";
    private const string ClientId = "billing-service";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly ClientAssertionValidator _validator;
    private readonly ECDsa _ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _otherEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly Client _client;

    public ClientAssertionValidatorTests()
    {
        _validator = new ClientAssertionValidator(_time);
        var ecKey = TestDpop.EcJwk(_ec);
        ecKey["kid"] = "ec-1";
        var rsaKey = TestDpop.RsaJwk(_rsa);
        rsaKey["kid"] = "rsa-1";
        var psKey = TestDpop.RsaJwk(_rsa);
        psKey["kid"] = "ps-only";
        psKey["alg"] = "PS256";
        _client = NewClient(new JsonObject { ["keys"] = new JsonArray(ecKey, rsaKey, psKey) }.ToJsonString());
    }

    public void Dispose()
    {
        _ec.Dispose();
        _otherEc.Dispose();
        _rsa.Dispose();
    }

    private static Client NewClient(string? jwks)
    {
        var client = Client.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), ClientId, "Billing", ClientType.Confidential, [GrantType.ClientCredentials],
            ["invoices.read"], [], requireConsent: false, overrides: null, Now, ["https://api.example.com"]);
        if (jwks is not null)
        {
            client.UsePrivateKeyJwt(jwks);
        }

        return client;
    }

    private static JsonObject Header(string alg = "ES256", string? kid = "ec-1")
    {
        var header = new JsonObject { ["alg"] = alg };
        if (kid is not null)
        {
            header["kid"] = kid;
        }

        return header;
    }

    private static JsonObject Payload(long? exp = null, string iss = ClientId, string sub = ClientId) => new()
    {
        ["iss"] = iss,
        ["sub"] = sub,
        ["aud"] = Issuer,
        ["jti"] = "jti-1",
        ["exp"] = exp ?? Now.AddMinutes(1).ToUnixTimeSeconds(),
        ["iat"] = Now.ToUnixTimeSeconds(),
    };

    private string Es256(JsonObject? header = null, JsonObject? payload = null) =>
        TestAssertion.Sign(header ?? Header(), payload ?? Payload(), _ec);

    private Result<ClientAssertion> Validate(string assertion, Client? client = null) =>
        _validator.Validate(assertion, client ?? _client, Issuer);

    private static void AssertRefused(Result<ClientAssertion> result, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(OAuthError.InvalidClientCode, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
    }

    [Fact]
    public void Es256_assertion_from_a_registered_key_is_valid()
    {
        var result = Validate(Es256());

        Assert.Equal(new ClientAssertion("jti-1", Now.AddMinutes(1)), result.Value);
    }

    [Theory]
    [InlineData("RS256", "rsa-1")]
    [InlineData("PS256", "rsa-1")]
    [InlineData("PS256", "ps-only")]
    public void Rsa_assertions_are_valid(string alg, string kid)
    {
        var padding = alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        var result = Validate(TestAssertion.Sign(Header(alg, kid), Payload(), _rsa, padding));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Key_that_names_its_algorithm_refuses_another()
    {
        AssertRefused(Validate(TestAssertion.Sign(Header("RS256", "ps-only"), Payload(), _rsa)), "kid unknown or key not valid for alg");
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES384")]
    public void Other_algorithms_are_refused(string alg)
    {
        AssertRefused(Validate(Es256(Header(alg))), "alg not supported");
    }

    [Fact]
    public void Key_type_must_match_the_algorithm()
    {
        AssertRefused(Validate(TestAssertion.Sign(Header("RS256", "ec-1"), Payload(), _rsa)), "kid unknown or key not valid for alg");
    }

    [Theory]
    [InlineData(null, "kid missing")]
    [InlineData("unknown", "kid unknown or key not valid for alg")]
    public void Assertion_must_name_a_registered_key(string? kid, string reason)
    {
        AssertRefused(Validate(Es256(Header(kid: kid))), reason);
    }

    [Fact]
    public void Crit_header_is_refused()
    {
        var header = Header();
        header["crit"] = new JsonArray("exp");

        AssertRefused(Validate(Es256(header)), "crit header");
    }

    [Theory]
    [InlineData("JWT", true)]
    [InlineData("client-authentication+jwt", true)]
    [InlineData("application/client-authentication+jwt", true)]
    [InlineData("dpop+jwt", false)]
    [InlineData("at+jwt", false)]
    public void Typ_must_not_name_another_kind_of_jwt(string typ, bool valid)
    {
        var header = Header();
        header["typ"] = typ;

        var result = Validate(Es256(header));

        Assert.Equal(valid, result.IsSuccess);
    }

    [Theory]
    [InlineData("iss", "other-client", "iss is not the client_id")]
    [InlineData("sub", "other-client", "sub is not the client_id")]
    [InlineData("aud", "https://acme.example.com/oauth/v1/token", "aud is not the issuer")]
    [InlineData("aud", "https://other.example.com", "aud is not the issuer")]
    [InlineData("jti", "", "jti missing or too long")]
    public void Claims_must_name_this_client_and_this_issuer(string claim, string value, string reason)
    {
        var payload = Payload();
        payload[claim] = value;

        AssertRefused(Validate(Es256(payload: payload)), reason);
    }

    [Fact]
    public void Aud_as_an_array_is_refused()
    {
        // D48: one string only, also when the array holds the issuer.
        var payload = Payload();
        payload["aud"] = new JsonArray(Issuer);

        AssertRefused(Validate(Es256(payload: payload)), "aud is not the issuer");
    }

    [Fact]
    public void Missing_exp_or_jti_is_refused()
    {
        var noExp = Payload();
        noExp.Remove("exp");
        var noJti = Payload();
        noJti.Remove("jti");

        AssertRefused(Validate(Es256(payload: noExp)), "exp missing");
        AssertRefused(Validate(Es256(payload: noJti)), "jti missing or too long");
    }

    [Fact]
    public void Exp_allows_the_clock_difference_and_the_lifetime_limit()
    {
        var skew = (long)ClientAssertionTypes.MaxClockDifference.TotalSeconds;
        var longest = (long)(ClientAssertionTypes.MaxLifetime.TotalSeconds + skew);
        var now = Now.ToUnixTimeSeconds();

        Assert.True(Validate(Es256(payload: Payload(exp: now - skew + 1))).IsSuccess);
        AssertRefused(Validate(Es256(payload: Payload(exp: now - skew))), "expired");
        Assert.True(Validate(Es256(payload: Payload(exp: now + longest))).IsSuccess);
        AssertRefused(Validate(Es256(payload: Payload(exp: now + longest + 1))), "exp too far in the future");
    }

    [Theory]
    [InlineData("iat")]
    [InlineData("nbf")]
    public void Iat_and_nbf_must_not_be_in_the_future(string claim)
    {
        var skew = (long)ClientAssertionTypes.MaxClockDifference.TotalSeconds;
        var future = Payload();
        future[claim] = Now.ToUnixTimeSeconds() + skew + 1;
        var text = Payload();
        text[claim] = "now";
        var edge = Payload();
        edge[claim] = Now.ToUnixTimeSeconds() + skew;

        AssertRefused(Validate(Es256(payload: future)), claim + " in the future or not a number");
        AssertRefused(Validate(Es256(payload: text)), claim + " in the future or not a number");
        Assert.True(Validate(Es256(payload: edge)).IsSuccess);
    }

    [Fact]
    public void Signature_from_another_key_or_over_other_data_is_refused()
    {
        var valid = Es256();
        var parts = valid.Split('.');
        var otherPayload = Payload();
        otherPayload["jti"] = "jti-2";

        AssertRefused(Validate(TestAssertion.Sign(Header(), Payload(), _otherEc)), "signature does not verify");
        AssertRefused(Validate(parts[0] + "." + TestJwt.Encode(otherPayload) + "." + parts[2]), "signature does not verify");
        AssertRefused(Validate(parts[0] + "." + parts[1] + ".%%%"), "signature does not verify");
    }

    [Theory]
    [InlineData("", "assertion missing or too long")]
    [InlineData("a.b", "assertion is not a compact JWS")]
    [InlineData("a.b.c.d", "assertion is not a compact JWS")]
    [InlineData("bm90LWpzb24.e30.c2ln", "header is not a JSON object")]
    public void Malformed_assertions_are_refused(string assertion, string reason)
    {
        AssertRefused(Validate(assertion), reason);
    }

    [Fact]
    public void Payload_that_is_not_a_json_object_is_refused()
    {
        var header = TestJwt.Encode(Header());

        AssertRefused(Validate(header + ".bm90LWpzb24.c2ln"), "payload is not a JSON object");
    }

    [Fact]
    public void Wrong_typ_has_its_own_reason()
    {
        var header = Header();
        header["typ"] = "dpop+jwt";

        AssertRefused(Validate(Es256(header)), "typ is another kind of JWT");
    }

    [Fact]
    public void Jti_may_have_256_characters()
    {
        var longest = Payload();
        longest["jti"] = new string('j', 256);
        var tooLong = Payload();
        tooLong["jti"] = new string('j', 257);

        Assert.True(Validate(Es256(payload: longest)).IsSuccess);
        AssertRefused(Validate(Es256(payload: tooLong)), "jti missing or too long");
    }

    /// <summary>A valid assertion of exactly <paramref name="length"/> characters, padded with an extra claim.</summary>
    private string AssertionOfLength(int length)
    {
        for (var pad = 0; pad < length; pad++)
        {
            foreach (var typ in (string?[])[null, "JWT"])
            {
                var header = Header();
                if (typ is not null)
                {
                    header["typ"] = typ;
                }

                var payload = Payload();
                payload["pad"] = new string('p', pad);
                var assertion = Es256(header, payload);
                if (assertion.Length == length)
                {
                    return assertion;
                }
            }
        }

        throw new InvalidOperationException("No padding gives this length.");
    }

    [Fact]
    public void Assertion_may_have_4096_characters()
    {
        var longest = AssertionOfLength(4096);
        var tooLong = AssertionOfLength(4097);

        Assert.True(Validate(longest).IsSuccess);
        Assert.Equal(ClientId, _validator.ReadClientId(longest));
        AssertRefused(Validate(tooLong), "assertion missing or too long");
        Assert.Null(_validator.ReadClientId(tooLong));
    }

    [Fact]
    public void Assertion_over_the_size_limit_is_refused()
    {
        AssertRefused(Validate(new string('a', 4097)), "assertion missing or too long");
    }

    [Fact]
    public void Client_without_keys_is_refused()
    {
        AssertRefused(Validate(Es256(), NewClient(jwks: null)), "client has no registered keys");
    }

    [Fact]
    public void Exp_with_a_fraction_rounds_up()
    {
        var payload = Payload();
        payload["exp"] = Now.ToUnixTimeSeconds() + 30.2;

        Assert.Equal(Now.AddSeconds(31), Validate(Es256(payload: payload)).Value.ExpiresAt);
    }

    [Fact]
    public void Client_id_is_read_from_sub_without_a_signature_check()
    {
        Assert.Equal("someone", _validator.ReadClientId(TestAssertion.Sign(Header(), Payload(sub: "someone"), _otherEc)));
        Assert.Null(_validator.ReadClientId("not-a-jwt"));
        Assert.Null(_validator.ReadClientId(null!));
        Assert.Null(_validator.ReadClientId(string.Empty));
        Assert.Null(_validator.ReadClientId(new string('a', 4097)));
        Assert.Null(_validator.ReadClientId(TestJwt.Encode(Header()) + "." + TestJwt.Encode(new JsonObject()) + ".sig"));
    }
}
