using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Heimdall.Application.Keys;
using Heimdall.Application.UserInfo;
using Heimdall.Infrastructure.Keys;

namespace Heimdall.UnitTests.Infrastructure;

public sealed class AccessTokenValidatorTests : IDisposable
{
    private const int MaxTokenLength = 8 * 1024;
    private static readonly DateTimeOffset Expiry = new(2026, 10, 18, 12, 5, 0, TimeSpan.Zero);

    private readonly Guid _tenantId = Guid.CreateVersion7();
    private readonly RSA _key = RSA.Create(2048);
    private readonly RSA _otherKey = RSA.Create(2048);
    private readonly FakeKeyCache _cache = new();
    private readonly AccessTokenValidator _validator;
    private readonly string _kid;

    public AccessTokenValidatorTests()
    {
        _validator = new AccessTokenValidator(_cache);
        var jwk = JwkOf(_key);
        _kid = jwk.Kid;
        _cache.Keys[_tenantId] = [jwk];
    }

    public void Dispose()
    {
        _key.Dispose();
        _otherKey.Dispose();
    }

    private static RsaPublicJwk JwkOf(RSA rsa)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        return RsaPublicJwk.FromPublicParameters(
            Base64Url.EncodeToString(parameters.Modulus!),
            Base64Url.EncodeToString(parameters.Exponent!));
    }

    private JsonObject Header() => new() { ["alg"] = "RS256", ["typ"] = "at+jwt", ["kid"] = _kid };

    private static JsonObject Payload() => new()
    {
        ["iss"] = "https://acme.example.com",
        ["sub"] = "user-1",
        ["aud"] = "https://acme.example.com/oauth/v1/userinfo",
        ["client_id"] = "spa",
        ["scope"] = "openid email",
        ["exp"] = Expiry.ToUnixTimeSeconds(),
    };

    private static string Encode(JsonNode node) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(node.ToJsonString()));

    private string Sign(JsonNode header, JsonNode payload, RSA? key = null) => SignSegments(Encode(header), Encode(payload), key);

    private string SignSegments(string header, string payload, RSA? key = null)
    {
        var input = header + "." + payload;
        var signature = (key ?? _key).SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return input + "." + Base64Url.EncodeToString(signature);
    }

    private ValueTask<VerifiedAccessToken?> Validate(string token, Guid? tenantId = null) =>
        _validator.ValidateAsync(tenantId ?? _tenantId, token, CancellationToken.None);

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

    [Fact]
    public async Task Valid_token_returns_its_claims()
    {
        var token = await Validate(Sign(Header(), Payload()));

        Assert.NotNull(token);
        Assert.Equal("https://acme.example.com", token.Issuer);
        Assert.Equal("user-1", token.Subject);
        Assert.Equal("https://acme.example.com/oauth/v1/userinfo", token.Audience);
        Assert.Equal("spa", token.ClientId);
        Assert.Equal(["openid", "email"], token.Scopes);
        Assert.Equal(Expiry, token.ExpiresAt);
    }

    [Fact]
    public async Task The_same_key_validates_many_tokens()
    {
        Assert.NotNull(await Validate(Sign(Header(), Payload())));
        Assert.NotNull(await Validate(Sign(Header(), With(Payload(), "sub", "user-2"))));
    }

    [Theory]
    [InlineData("application/at+jwt")]
    [InlineData("AT+JWT")]
    [InlineData("Application/At+Jwt")]
    public async Task Typ_values_of_RFC_9068_are_accepted(string typ)
    {
        Assert.NotNull(await Validate(Sign(With(Header(), "typ", typ), Payload())));
    }

    [Theory]
    [InlineData("JWT")] // An ID token cannot pass as an access token.
    [InlineData("at+jwt ")]
    [InlineData("")]
    public async Task Other_typ_values_are_refused(string typ)
    {
        Assert.Null(await Validate(Sign(With(Header(), "typ", typ), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Missing_typ_is_refused()
    {
        Assert.Null(await Validate(Sign(Without(Header(), "typ"), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("RS512")]
    [InlineData("PS256")]
    [InlineData("rs256")]
    public async Task Algorithms_other_than_RS256_are_refused(string alg)
    {
        Assert.Null(await Validate(Sign(With(Header(), "alg", alg), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Missing_alg_is_refused()
    {
        Assert.Null(await Validate(Sign(Without(Header(), "alg"), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Alg_that_is_not_a_string_is_refused()
    {
        Assert.Null(await Validate(Sign(With(Header(), "alg", 256), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Crit_header_is_refused()
    {
        // RFC 7515, section 4.1.11: a recipient that does not understand a listed extension must reject the token.
        Assert.Null(await Validate(Sign(With(Header(), "crit", new JsonArray("exp")), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Missing_kid_is_refused()
    {
        Assert.Null(await Validate(Sign(Without(Header(), "kid"), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Empty_kid_is_refused()
    {
        Assert.Null(await Validate(Sign(With(Header(), "kid", ""), Payload())));
        Assert.Equal(0, _cache.Reads);
    }

    [Fact]
    public async Task Kid_that_is_not_published_is_refused()
    {
        Assert.Null(await Validate(Sign(With(Header(), "kid", JwkOf(_otherKey).Kid), Payload(), _otherKey)));
    }

    [Fact]
    public async Task Key_of_another_tenant_is_refused()
    {
        var otherTenant = Guid.CreateVersion7();
        _cache.Keys[otherTenant] = [JwkOf(_otherKey)];

        Assert.Null(await Validate(Sign(Header(), Payload()), otherTenant));
    }

    [Fact]
    public async Task Jku_and_x5u_are_never_followed()
    {
        // The header points to an attacker's key, but only the published kid counts.
        JsonObject Pointing() => With(With(Header(), "jku", "https://evil.example.com/jwks"), "x5u", "https://evil.example.com/cert");

        Assert.Null(await Validate(Sign(With(Pointing(), "kid", "attacker-kid"), Payload(), _otherKey)));
        Assert.NotNull(await Validate(Sign(Pointing(), Payload())));
    }

    [Fact]
    public async Task Signature_of_another_key_is_refused()
    {
        Assert.Null(await Validate(Sign(Header(), Payload(), _otherKey)));
    }

    [Fact]
    public async Task Changed_payload_is_refused()
    {
        var parts = Sign(Header(), Payload()).Split('.');
        var changed = Encode(With(Payload(), "sub", "admin"));

        Assert.Null(await Validate(parts[0] + "." + changed + "." + parts[2]));
    }

    [Fact]
    public async Task Changed_header_is_refused()
    {
        var parts = Sign(Header(), Payload()).Split('.');
        var changed = Encode(With(Header(), "typ", "application/at+jwt"));

        Assert.Null(await Validate(changed + "." + parts[1] + "." + parts[2]));
    }

    [Fact]
    public async Task Empty_signature_is_refused()
    {
        var parts = Sign(Header(), Payload()).Split('.');

        Assert.Null(await Validate(parts[0] + "." + parts[1] + "."));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("a.b.c.d.e")] // JWE compact form
    public async Task Wrong_number_of_parts_is_refused(string token)
    {
        Assert.Null(await Validate(token));
    }

    [Fact]
    public async Task Valid_token_with_an_extra_part_is_refused()
    {
        Assert.Null(await Validate(Sign(Header(), Payload()) + ".extra"));
    }

    [Fact]
    public async Task Valid_header_and_payload_without_a_signature_part_is_refused()
    {
        Assert.Null(await Validate(Encode(Header()) + "." + Encode(Payload())));
    }

    [Fact]
    public async Task Token_of_the_maximum_length_is_checked()
    {
        var token = SignedOfLength(MaxTokenLength);

        Assert.Equal(MaxTokenLength, token.Length);
        Assert.NotNull(await Validate(token));
    }

    [Fact]
    public async Task Longer_token_is_refused_before_decoding()
    {
        var token = SignedOfLength(MaxTokenLength + 1);

        Assert.Equal(MaxTokenLength + 1, token.Length);
        Assert.Null(await Validate(token));
        Assert.Equal(0, _cache.Reads);
    }

    /// <summary>A valid token, padded with filler claims to exactly <paramref name="length"/> characters.</summary>
    /// <remarks>
    /// Base64url text never has a length of 1 mod 4, so the payload filler alone cannot reach every length. A short
    /// header filler moves the header length too.
    /// </remarks>
    private string SignedOfLength(int length)
    {
        var start = Sign(With(Header(), "p", ""), With(Payload(), "filler", "")).Length;
        var estimate = (length - start) * 3 / 4;
        for (var headerPad = 0; headerPad < 4; headerPad++)
        {
            for (var size = estimate - 8; size <= estimate + 8; size++)
            {
                var token = Sign(With(Header(), "p", new string('h', headerPad)), With(Payload(), "filler", new string('x', size)));
                if (token.Length == length)
                {
                    return token;
                }
            }
        }

        throw new InvalidOperationException("No filler length gives that token length.");
    }

    [Theory]
    [InlineData("eyJh=")] // padding
    [InlineData("eyJh+")] // base64, not base64url
    [InlineData("eyJh/")]
    [InlineData("eyJh bGc")] // white space, which Base64Url.IsValid ignores
    [InlineData("eyJh\nbGc")]
    public async Task Header_that_is_not_strict_base64url_is_refused(string header)
    {
        var parts = Sign(Header(), Payload()).Split('.');

        Assert.Null(await Validate(header + "." + parts[1] + "." + parts[2]));
        Assert.Equal(0, _cache.Reads);
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("\t")]
    public async Task White_space_in_a_signed_header_is_refused(string space)
    {
        // The decoder skips white space. Without the strict check, one token would have many valid spellings.
        var header = Encode(Header());
        var spaced = header[..10] + space + header[10..];

        Assert.NotNull(await Validate(SignSegments(header, Encode(Payload()))));
        Assert.Null(await Validate(SignSegments(spaced, Encode(Payload()))));
    }

    [Fact]
    public async Task White_space_in_the_signature_is_refused()
    {
        var parts = Sign(Header(), Payload()).Split('.');

        Assert.Null(await Validate(parts[0] + "." + parts[1] + "." + parts[2][..20] + "\n" + parts[2][20..]));
    }

    [Fact]
    public async Task Header_with_an_impossible_base64url_length_is_refused()
    {
        // One leftover character can never decode.
        var parts = Sign(Header(), Payload()).Split('.');

        Assert.Null(await Validate("a" + "." + parts[1] + "." + parts[2]));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[\"RS256\"]")]
    [InlineData("\"RS256\"")]
    public async Task Header_that_is_not_a_json_object_is_refused(string header)
    {
        var payload = Encode(Payload());
        var encoded = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header));

        Assert.Null(await Validate(SignSegments(encoded, payload)));
    }

    [Fact]
    public async Task Deeply_nested_header_is_refused()
    {
        JsonNode nested = new JsonObject();
        for (var i = 0; i < 9; i++)
        {
            nested = new JsonObject { ["x"] = nested };
        }

        Assert.Null(await Validate(Sign(With(Header(), "ext", nested), Payload())));
    }

    [Fact]
    public async Task Header_nested_to_the_depth_limit_is_accepted()
    {
        // Depth 8 counts the header object itself.
        JsonNode nested = new JsonObject();
        for (var i = 0; i < 6; i++)
        {
            nested = new JsonObject { ["x"] = nested };
        }

        Assert.NotNull(await Validate(Sign(With(Header(), "ext", nested), Payload())));
    }

    [Theory]
    [InlineData("iss")]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("client_id")]
    [InlineData("exp")]
    public async Task Payload_without_a_required_claim_is_refused(string claim)
    {
        Assert.Null(await Validate(Sign(Header(), Without(Payload(), claim))));
    }

    [Theory]
    [InlineData("iss")]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("client_id")]
    public async Task Empty_required_claim_is_refused(string claim)
    {
        Assert.Null(await Validate(Sign(Header(), With(Payload(), claim, ""))));
    }

    [Fact]
    public async Task Audience_array_is_refused()
    {
        // Heimdall issues one audience as a string (D22). An array is not a Heimdall token.
        Assert.Null(await Validate(Sign(Header(), With(Payload(), "aud", new JsonArray("a", "b")))));
    }

    [Theory]
    [InlineData("\"1792325100\"")]
    [InlineData("1792325100.5")]
    [InlineData("99999999999999999999")]
    public async Task Exp_that_is_not_an_integer_is_refused(string exp)
    {
        Assert.Null(await Validate(Sign(Header(), With(Payload(), "exp", JsonNode.Parse(exp)))));
    }

    [Fact]
    public async Task Exp_out_of_the_date_range_is_refused()
    {
        Assert.Null(await Validate(Sign(Header(), With(Payload(), "exp", long.MaxValue))));
    }

    [Fact]
    public async Task Missing_scope_is_an_empty_list()
    {
        Assert.Empty((await Validate(Sign(Header(), Without(Payload(), "scope"))))!.Scopes);
    }

    [Fact]
    public async Task Scope_that_is_not_a_string_is_an_empty_list()
    {
        Assert.Empty((await Validate(Sign(Header(), With(Payload(), "scope", new JsonArray("openid")))))!.Scopes);
    }

    [Fact]
    public async Task Extra_spaces_in_scope_are_ignored()
    {
        Assert.Equal(["openid", "email"], (await Validate(Sign(Header(), With(Payload(), "scope", " openid  email "))))!.Scopes);
    }

    [Fact]
    public async Task Payload_that_is_not_a_json_object_is_refused()
    {
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("[1,2,3]"));

        Assert.Null(await Validate(SignSegments(Encode(Header()), payload)));
    }

    [Fact]
    public async Task Payload_that_is_not_json_is_refused()
    {
        var payload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{\"iss\":"));

        Assert.Null(await Validate(SignSegments(Encode(Header()), payload)));
    }

    private sealed class FakeKeyCache : ISigningKeyCache
    {
        public Dictionary<Guid, IReadOnlyList<RsaPublicJwk>> Keys { get; } = [];

        public int Reads { get; private set; }

        public ValueTask<ActiveSigningKey?> GetActiveKeyAsync(Guid tenantId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask<IReadOnlyList<RsaPublicJwk>> GetPublishedKeysAsync(Guid tenantId, CancellationToken cancellationToken)
        {
            Reads++;
            return ValueTask.FromResult(Keys.TryGetValue(tenantId, out var keys) ? keys : []);
        }

        public void Invalidate(Guid tenantId)
        {
        }
    }
}
