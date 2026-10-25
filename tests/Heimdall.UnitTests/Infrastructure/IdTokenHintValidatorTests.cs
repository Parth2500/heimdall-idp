using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Heimdall.Application.Logout;
using Heimdall.Infrastructure.Keys;

namespace Heimdall.UnitTests.Infrastructure;

/// <summary>D30: an id_token_hint counts only when the tenant signed it as an ID token. Its exp does not count.</summary>
public sealed class IdTokenHintValidatorTests : IDisposable
{
    private const string Sid = "sid-of-the-session-001";

    private readonly Guid _tenantId = Guid.CreateVersion7();
    private readonly RSA _key = RSA.Create(2048);
    private readonly RSA _otherKey = RSA.Create(2048);
    private readonly FakeKeyCache _cache = new();
    private readonly IdTokenHintValidator _validator;
    private readonly string _kid;

    public IdTokenHintValidatorTests()
    {
        _validator = new IdTokenHintValidator(_cache);
        var jwk = TestJwt.JwkOf(_key);
        _kid = jwk.Kid;
        _cache.Keys[_tenantId] = [jwk];
    }

    public void Dispose()
    {
        _key.Dispose();
        _otherKey.Dispose();
    }

    private JsonObject Header() => new() { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = _kid };

    // An ID token from long ago: exp is in the past.
    private static JsonObject Payload() => new()
    {
        ["iss"] = "https://acme.example.com",
        ["sub"] = "user-1",
        ["aud"] = "spa",
        ["iat"] = 1_600_000_000,
        ["exp"] = 1_600_000_300,
        ["sid"] = Sid,
    };

    private string Sign(JsonNode header, JsonNode payload, RSA? key = null) =>
        TestJwt.SignSegments(TestJwt.Encode(header), TestJwt.Encode(payload), key ?? _key);

    private ValueTask<VerifiedIdTokenHint?> Validate(string token, Guid? tenantId = null) =>
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
    public async Task Expired_id_token_returns_its_claims()
    {
        var hint = await Validate(Sign(Header(), Payload()));

        Assert.NotNull(hint);
        Assert.Equal("https://acme.example.com", hint.Issuer);
        Assert.Equal("user-1", hint.Subject);
        Assert.Equal(["spa"], hint.Audiences);
        Assert.Equal(Sid, hint.Sid);
    }

    [Fact]
    public async Task Audience_array_returns_each_value()
    {
        var hint = await Validate(Sign(Header(), With(Payload(), "aud", new JsonArray("spa", "huginn"))));

        Assert.Equal(["spa", "huginn"], hint!.Audiences);
    }

    [Fact]
    public async Task Hint_without_a_sid_names_no_session() =>
        Assert.Null((await Validate(Sign(Header(), Without(Payload(), "sid"))))!.Sid);

    [Theory]
    [InlineData("at+jwt")] // An access token is not a hint.
    [InlineData("logout+jwt")] // Neither is a logout token.
    [InlineData("JWT ")]
    [InlineData("")]
    public async Task Other_typ_values_are_refused(string typ) =>
        Assert.Null(await Validate(Sign(With(Header(), "typ", typ), Payload())));

    [Fact]
    public async Task Lower_case_typ_is_accepted() =>
        Assert.NotNull(await Validate(Sign(With(Header(), "typ", "jwt"), Payload())));

    [Fact]
    public async Task Missing_typ_is_refused() =>
        Assert.Null(await Validate(Sign(Without(Header(), "typ"), Payload())));

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("RS512")]
    public async Task Other_algorithms_are_refused(string alg) =>
        Assert.Null(await Validate(Sign(With(Header(), "alg", alg), Payload())));

    [Fact]
    public async Task Key_of_another_signer_is_refused() =>
        Assert.Null(await Validate(Sign(Header(), Payload(), _otherKey)));

    [Fact]
    public async Task Key_of_another_tenant_is_refused()
    {
        var other = Guid.CreateVersion7();
        _cache.Keys[other] = [];

        Assert.Null(await Validate(Sign(Header(), Payload()), other));
    }

    [Fact]
    public async Task Changed_payload_is_refused()
    {
        var parts = Sign(Header(), Payload()).Split('.');
        var changed = TestJwt.Encode(With(Payload(), "sid", "sid-of-another-one-002"));

        Assert.Null(await Validate(parts[0] + "." + changed + "." + parts[2]));
    }

    [Theory]
    [InlineData("iss")]
    [InlineData("sub")]
    [InlineData("aud")]
    public async Task Missing_required_claim_is_refused(string claim) =>
        Assert.Null(await Validate(Sign(Header(), Without(Payload(), claim))));

    [Theory]
    [InlineData("42")]
    [InlineData("\"\"")]
    [InlineData("[]")]
    [InlineData("[\"spa\", 42]")]
    [InlineData("[\"spa\", \"\"]")]
    [InlineData("{}")]
    public async Task Unreadable_audience_is_refused(string aud) =>
        Assert.Null(await Validate(Sign(Header(), With(Payload(), "aud", JsonNode.Parse(aud)))));

    // D31: a sid that is not one of Heimdall's could never match a session, so the hint is refused.
    [Theory]
    [InlineData("\"short\"")]
    [InlineData("\"sid+of/the=session-001\"")]
    [InlineData("\"\"")]
    [InlineData("42")]
    [InlineData("null")]
    public async Task Unreadable_sid_is_refused(string sid) =>
        Assert.Null(await Validate(Sign(Header(), With(Payload(), "sid", JsonNode.Parse(sid)))));

    [Theory]
    [InlineData("")]
    [InlineData("one.two")]
    [InlineData("a.b.c.d")]
    public async Task Malformed_token_is_refused(string token) =>
        Assert.Null(await Validate(token));
}
