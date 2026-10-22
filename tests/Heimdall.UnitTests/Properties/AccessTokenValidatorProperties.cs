using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CsCheck;
using Heimdall.Infrastructure.Keys;
using Heimdall.UnitTests.Infrastructure;

namespace Heimdall.UnitTests.Properties;

public sealed class AccessTokenValidatorProperties : IDisposable
{
    private readonly Guid _tenantId = Guid.CreateVersion7();
    private readonly RSA _key = RSA.Create(2048);
    private readonly FakeKeyCache _cache = new();
    private readonly AccessTokenValidator _validator;
    private readonly string _kid;

    public AccessTokenValidatorProperties()
    {
        _validator = new AccessTokenValidator(_cache);
        var jwk = TestJwt.JwkOf(_key);
        _kid = jwk.Kid;
        _cache.Keys[_tenantId] = [jwk];
    }

    public void Dispose() => _key.Dispose();

    private static readonly string[] RequiredClaims = ["iss", "sub", "aud", "client_id"];

    private static readonly Gen<JsonNode?> JsonValue = Gen.OneOf<JsonNode?>(
        Gen.Const<JsonNode?>((JsonNode?)null),
        Gen.Bool.Select(b => (JsonNode?)System.Text.Json.Nodes.JsonValue.Create(b)),
        Gen.Long.Select(n => (JsonNode?)System.Text.Json.Nodes.JsonValue.Create(n)),
        Gen.Double.Where(double.IsFinite).Select(d => (JsonNode?)System.Text.Json.Nodes.JsonValue.Create(d)),
        Generators.UnicodeText.Select(s => (JsonNode?)System.Text.Json.Nodes.JsonValue.Create(s)));

    private static readonly Gen<JsonNode?> AnyJson = Gen.Recursive<JsonNode?>((depth, inner) =>
        depth > 10
            ? JsonValue
            : Gen.Frequency(
                (3, JsonValue),
                (1, inner.Array[0, 4].Select(items => (JsonNode?)new JsonArray(items.Select(Clone).ToArray()))),
                (1, Gen.Dictionary(Generators.UnicodeText, inner)[0, 4]
                    .Select(d => (JsonNode?)new JsonObject(d.Select(p => KeyValuePair.Create(p.Key, Clone(p.Value))))))));

    /// <summary>A claim value as the validator's rules see it: a string, maybe empty, or something else.</summary>
    private static readonly Gen<JsonNode?> ClaimValue = Gen.Frequency(
        (4, Generators.UnicodeText.Select(s => (JsonNode?)System.Text.Json.Nodes.JsonValue.Create(s))),
        (1, AnyJson));

    private static JsonNode? Clone(JsonNode? node) => node?.DeepClone();

    private Task<Heimdall.Application.UserInfo.VerifiedAccessToken?> Validate(string token) =>
        _validator.ValidateAsync(_tenantId, token, CancellationToken.None).AsTask();

    private string Sign(JsonNode header, JsonNode payload) => TestJwt.SignSegments(TestJwt.Encode(header), TestJwt.Encode(payload), _key);

    private JsonObject ValidHeader() => new() { ["alg"] = "RS256", ["typ"] = "at+jwt", ["kid"] = _kid };

    [Fact]
    public async Task Any_text_is_refused_without_an_exception()
    {
        await Generators.TokenLike.SampleAsync(async token => Assert.Null(await Validate(token)), iter: 10_000);
    }

    [Fact]
    public async Task Any_three_base64url_segments_are_refused_without_an_exception()
    {
        var segment = Gen.Frequency(
            (1, Gen.Byte.Array[0, 64].Select(b => Base64Url.EncodeToString(b))),
            (1, AnyJson.Select(n => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(n?.ToJsonString() ?? "null")))));

        await Gen.Select(segment, segment, segment)
            .SampleAsync(async (h, p, s) => Assert.Null(await Validate(h + "." + p + "." + s)), iter: 5_000);
    }

    [Fact]
    public async Task Signed_headers_with_any_values_never_throw_and_pass_only_when_every_rule_holds()
    {
        var header = Gen.Select(
            Gen.Frequency((3, Gen.Const<JsonNode?>("RS256")), (1, ClaimValue)),
            Gen.Frequency((3, Gen.OneOfConst<JsonNode?>("at+jwt", "application/at+jwt", "AT+JWT")), (1, ClaimValue)),
            Gen.Frequency((3, Gen.Const<JsonNode?>("kid")), (1, ClaimValue)),
            Gen.Frequency((5, Gen.Const<JsonNode?>((JsonNode?)null)), (1, AnyJson)));

        await header.SampleAsync(async (alg, typ, kid, crit) =>
        {
            var node = new JsonObject { ["alg"] = Clone(alg), ["typ"] = Clone(typ), ["kid"] = Clone(kid) };
            if (kid?.ToString() == "kid")
            {
                node["kid"] = _kid;
            }

            if (crit is not null)
            {
                node["crit"] = Clone(crit);
            }

            var result = await Validate(Sign(node, Payload("user-1")));

            using var seen = JsonDocument.Parse(node.ToJsonString());
            var h = seen.RootElement;
            var valid = Text(h, "alg") == "RS256"
                && Text(h, "typ") is { } t && (t.Equals("at+jwt", StringComparison.OrdinalIgnoreCase) || t.Equals("application/at+jwt", StringComparison.OrdinalIgnoreCase))
                && Text(h, "kid") == _kid
                && !h.TryGetProperty("crit", out _);
            Assert.Equal(valid, result is not null);
        }, iter: 400);
    }

    [Fact]
    public async Task Signed_payloads_with_any_values_never_throw_and_pass_only_when_every_claim_is_valid()
    {
        var payload = Gen.Select(ClaimValue, ClaimValue, ClaimValue, ClaimValue, Gen.Frequency((3, Gen.Long[0, 4_102_444_800L].Select(n => (JsonNode?)n)), (1, AnyJson)));

        await payload.SampleAsync(async (iss, sub, aud, clientId, exp) =>
        {
            var node = new JsonObject
            {
                ["iss"] = Clone(iss),
                ["sub"] = Clone(sub),
                ["aud"] = Clone(aud),
                ["client_id"] = Clone(clientId),
                ["exp"] = Clone(exp),
            };

            var result = await Validate(Sign(ValidHeader(), node));

            using var seen = JsonDocument.Parse(node.ToJsonString());
            var p = seen.RootElement;
            var valid = RequiredClaims.All(c => Text(p, c) is { Length: > 0 })
                && p.TryGetProperty("exp", out var e) && e.ValueKind == JsonValueKind.Number
                && e.TryGetInt64(out var seconds) && seconds is >= -62_135_596_800L and <= 253_402_300_799L;
            Assert.Equal(valid, result is not null);
        }, iter: 400);
    }

    [Fact]
    public async Task Valid_claims_of_any_text_come_back_unchanged()
    {
        var text = Generators.UnicodeText.Where(s => s.Length > 0);
        var claims = Gen.Select(text, text, text, text, Generators.ScopeToken.Array[0, 5], Gen.Long[-62_135_596_800L, 253_402_300_799L]);

        await claims.SampleAsync(async c =>
        {
            var (iss, sub, aud, clientId, scopes, exp) = c;
            var node = new JsonObject
            {
                ["iss"] = iss,
                ["sub"] = sub,
                ["aud"] = aud,
                ["client_id"] = clientId,
                ["scope"] = string.Join(' ', scopes),
                ["exp"] = exp,
            };

            var token = await Validate(Sign(ValidHeader(), node));

            Assert.NotNull(token);
            Assert.Equal(iss, token.Issuer);
            Assert.Equal(sub, token.Subject);
            Assert.Equal(aud, token.Audience);
            Assert.Equal(clientId, token.ClientId);
            Assert.Equal(scopes, token.Scopes);
            Assert.Equal(exp, token.ExpiresAt.ToUnixTimeSeconds());
        }, iter: 300);
    }

    [Fact]
    public async Task Changing_any_one_character_of_a_valid_token_makes_it_invalid()
    {
        var token = Sign(ValidHeader(), Payload("user-1"));
        Assert.NotNull(await Validate(token));

        var change = Gen.Select(Gen.Int[0, token.Length - 1], Gen.Char[Generators.Base64UrlChars + ".=+/ "]);

        await change.Where((i, c) => token[i] != c).SampleAsync(async (index, replacement) =>
        {
            var changed = string.Concat(token.AsSpan(0, index), replacement.ToString(), token.AsSpan(index + 1));

            Assert.Null(await Validate(changed));
        }, iter: 3_000);
    }

    private static JsonObject Payload(string subject) => new()
    {
        ["iss"] = "https://acme.example.com",
        ["sub"] = subject,
        ["aud"] = "https://acme.example.com/oauth/v1/userinfo",
        ["client_id"] = "spa",
        ["exp"] = 1_792_325_100,
    };

    /// <summary>The expected result is computed from the JSON as the validator reads it, not from the JsonNode objects.</summary>
    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
