using System.Net;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Tokens;
using Heimdall.Application.UserInfo;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

/// <summary>Introspection (RFC 7662, D36 to D39).</summary>
public class TokenIntrospectionTests
{
    private const string Issuer = "https://acme.example.com";
    private const string Api = "https://api.example.com";
    private const string Secret = "resource-server-secret";
    private const string Jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private const string AccessToken = "header.payload.signature";
    private const string RefreshValue = "the-refresh-token";
    private static readonly DateTimeOffset Now = new(2026, 10, 26, 12, 0, 0, TimeSpan.Zero);
    private static readonly TokenLifetimes Lifetimes = new(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(30));

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryTokenStore _tokens = new();
    private readonly FakeValidator _validator = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly TokenIntrospection _service;
    private readonly Client _resourceServer;
    private readonly Client _spa;
    private readonly User _user;
    private readonly Guid _userId;

    public TokenIntrospectionTests()
    {
        _service = new TokenIntrospection(new ClientAuthenticator(_clients, new FakeClientAssertionValidator(), new InMemoryClientAssertionReplayStore(), _time), _clients, _validator, _tokens, _audit, _time);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", "hash", Now.AddDays(-1));
        _userId = _user.Id;
        _tokens.Users.Add(_user);
        _resourceServer = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "orders-api", "Orders API", ClientType.Confidential,
            [GrantType.ClientCredentials], [], [], false, null, Now, ["https://billing.example.com"]);
        _resourceServer.UpdateResourceAudiences([Api]);
        _resourceServer.Approve();
        _clients.Add(_resourceServer, (Secret, null));

        _spa = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "spa", "SPA", ClientType.Public,
            [GrantType.AuthorizationCode, GrantType.RefreshToken], ["openid", "offline_access"], ["https://app.example.com/cb"], false, null, Now);
        _spa.Approve();
        _clients.Add(_spa);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private Task<Result<IntrospectionResult>> Introspect(string? token = AccessToken, string clientId = "orders-api", string? secret = Secret) =>
        _service.IntrospectAsync(Context, new IntrospectionRequest(clientId, secret, token), CancellationToken.None);

    private static VerifiedAccessToken Token(
        string audience = Api,
        string clientId = "spa",
        Guid? familyId = null,
        string issuer = Issuer,
        DateTimeOffset? expiresAt = null,
        string? jkt = null) =>
        new(issuer, "user-1", audience, clientId, ["openid", "orders.read"], expiresAt ?? Now.AddMinutes(5), jkt, familyId, Now.AddMinutes(-1));

    private TokenFamily AddFamily(Client client)
    {
        var family = TokenFamily.Start(Guid.CreateVersion7(), _tenant.Id, client.Id, _userId, Guid.CreateVersion7(), "openid offline_access", Lifetimes, Now, sid: "sid-of-the-session-001");
        _tokens.Families.Add(family);
        return family;
    }

    private RefreshToken AddRefreshToken(TokenFamily family, string value = RefreshValue)
    {
        var token = RefreshToken.Create(Guid.CreateVersion7(), _tenant.Id, family.Id, TokenHash.Compute(value), Now.AddMinutes(-2));
        _tokens.RefreshTokens.Add(token);
        return token;
    }

    private static void AssertInactive(Result<IntrospectionResult> result)
    {
        Assert.True(result.IsSuccess);
        Assert.Same(IntrospectionResult.Inactive, result.Value);
        Assert.Equal(new IntrospectionResult(false), result.Value);
    }

    // ---- The caller (D36)

    [Fact]
    public async Task Public_client_is_refused_and_audited()
    {
        var result = await Introspect(clientId: "spa", secret: null);

        Assert.Equal(OAuthError.InvalidClientCode, result.Error!.Code);
        var refused = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.IntrospectionRefused, refused.Type);
        Assert.Equal("spa", refused.Data["client_id"]);
        Assert.Equal(OAuthError.InvalidClientCode, refused.Data["error"]);
        Assert.Equal("public client at introspection", refused.Data["reason"]);
        Assert.Null(_validator.Called);
    }

    [Fact]
    public async Task Wrong_secret_is_refused_and_audited()
    {
        var result = await Introspect(secret: "wrong");

        Assert.Equal(OAuthError.InvalidClientCode, result.Error!.Code);
        Assert.Equal(AuditEventTypes.IntrospectionRefused, Assert.Single(_audit.Events).Type);
    }

    [Fact]
    public async Task Request_without_a_client_is_audited_with_an_empty_client_id()
    {
        await _service.IntrospectAsync(Context, new IntrospectionRequest(null, null, AccessToken), CancellationToken.None);

        Assert.Equal(string.Empty, Assert.Single(_audit.Events).Data["client_id"]);
    }

    [Fact]
    public async Task Long_client_id_is_cut_in_the_audit_event()
    {
        await Introspect(clientId: new string('c', 300), secret: "x");

        Assert.Equal(128, Assert.Single(_audit.Events).Data["client_id"].Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Missing_token_is_invalid_request(string? token) =>
        Assert.Equal(OAuthError.InvalidRequestCode, (await Introspect(token)).Error!.Code);

    // ---- Access tokens (D37, D38)

    [Fact]
    public async Task Token_for_a_served_audience_is_active_with_its_claims()
    {
        var family = AddFamily(_spa);
        _validator.Result = Token(familyId: family.Id);

        var result = await Introspect();

        Assert.True(result.IsSuccess);
        Assert.Equal(
            new IntrospectionResult(true, "openid orders.read", "spa", "user-1", Api, Issuer, Now.AddMinutes(5), Now.AddMinutes(-1), "Bearer"),
            result.Value);
        Assert.Equal((_tenant.Id, AccessToken), _validator.Called);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Bound_token_says_DPoP_and_names_its_key()
    {
        _validator.Result = Token(jkt: Jkt);

        var result = (await Introspect()).Value;

        Assert.Equal("DPoP", result.TokenType);
        Assert.Equal(Jkt, result.KeyThumbprint);
    }

    [Fact]
    public async Task Token_without_scope_has_no_scope()
    {
        _validator.Result = Token() with { Scopes = [] };

        Assert.Null((await Introspect()).Value.Scope);
    }

    [Fact]
    public async Task Client_sees_a_token_that_was_issued_to_it()
    {
        _validator.Result = Token(audience: "https://billing.example.com", clientId: "orders-api");

        Assert.True((await Introspect()).Value.Active);
    }

    [Fact]
    public async Task Token_for_another_audience_and_client_is_inactive()
    {
        _validator.Result = Token(audience: "https://billing.example.com", clientId: "spa");

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Audience_compares_by_exact_string()
    {
        _validator.Result = Token(audience: Api + "/");

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Token_that_fails_validation_is_inactive() =>
        AssertInactive(await Introspect());

    [Fact]
    public async Task Token_of_another_issuer_is_inactive()
    {
        _validator.Result = Token(issuer: "https://other.example.com");

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Token_is_inactive_at_its_exp()
    {
        _validator.Result = Token(expiresAt: Now);

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Token_is_active_one_tick_before_its_exp()
    {
        _validator.Result = Token(expiresAt: Now.AddTicks(1));

        Assert.True((await Introspect()).Value.Active);
    }

    [Theory]
    [InlineData(FamilyRevocationReason.UserLogout)]
    [InlineData(FamilyRevocationReason.ReuseDetected)]
    public async Task Token_of_a_revoked_family_is_inactive_before_its_exp(FamilyRevocationReason reason)
    {
        var family = AddFamily(_spa);
        family.Revoke(reason, Now.AddSeconds(-1));
        _validator.Result = Token(familyId: family.Id);

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Token_of_a_disabled_user_is_inactive_before_its_exp()
    {
        // As at /userinfo: a disabled user gets nothing with a valid token.
        var family = AddFamily(_spa);
        _user.Disable();
        _validator.Result = Token(familyId: family.Id);

        AssertInactive(await Introspect());
        Assert.Equal(1, _tokens.FamilyReads);
    }

    [Fact]
    public async Task Token_of_a_disabled_client_is_inactive()
    {
        _spa.Disable();
        _validator.Result = Token();

        AssertInactive(await Introspect());
        Assert.Equal(0, _tokens.FamilyReads);
    }

    [Fact]
    public async Task Token_of_an_unknown_client_is_inactive()
    {
        _validator.Result = Token(clientId: "deleted-app");

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Client_credentials_token_needs_no_read()
    {
        _validator.Result = Token();

        Assert.True((await Introspect()).Value.Active);
        Assert.Equal(0, _tokens.FamilyReads);
    }

    [Fact]
    public async Task Token_of_a_purged_family_is_inactive()
    {
        _validator.Result = Token(familyId: Guid.CreateVersion7());

        AssertInactive(await Introspect());
    }

    [Fact]
    public async Task Token_of_a_family_past_its_idle_limit_stays_active_until_exp()
    {
        // D38: only a revocation ends an access token early. The idle limit is about refresh.
        var family = AddFamily(_spa);
        InMemoryTokenStore.Set(family, nameof(TokenFamily.IdleExpiresAt), Now.AddSeconds(-1));
        _validator.Result = Token(familyId: family.Id);

        Assert.True((await Introspect()).Value.Active);
    }

    // ---- Refresh tokens (D37, D38)

    [Fact]
    public async Task Own_refresh_token_is_active_with_the_family_values()
    {
        var family = AddFamily(_resourceServer);
        var token = AddRefreshToken(family);

        var result = (await Introspect(RefreshValue)).Value;

        Assert.Equal(
            new IntrospectionResult(true, "openid offline_access", "orders-api", _userId.ToString(), null, Issuer, family.IdleExpiresAt, token.CreatedAt),
            result);
        Assert.Null(_validator.Called);
    }

    [Fact]
    public async Task Refresh_token_of_another_client_is_inactive()
    {
        AddRefreshToken(AddFamily(_spa));

        AssertInactive(await Introspect(RefreshValue));
    }

    [Fact]
    public async Task Used_refresh_token_is_inactive()
    {
        var token = AddRefreshToken(AddFamily(_resourceServer));
        token.Use(Guid.CreateVersion7(), Now.AddMinutes(-1));

        AssertInactive(await Introspect(RefreshValue));
    }

    [Fact]
    public async Task Refresh_token_of_a_revoked_family_is_inactive()
    {
        var family = AddFamily(_resourceServer);
        AddRefreshToken(family);
        family.Revoke(FamilyRevocationReason.UserLogout, Now.AddSeconds(-1));

        AssertInactive(await Introspect(RefreshValue));
    }

    [Fact]
    public async Task Refresh_token_of_a_disabled_user_is_inactive()
    {
        AddRefreshToken(AddFamily(_resourceServer));
        _user.Disable();

        AssertInactive(await Introspect(RefreshValue));
    }

    [Fact]
    public async Task Refresh_token_past_the_idle_limit_is_inactive()
    {
        var family = AddFamily(_resourceServer);
        AddRefreshToken(family);
        _time.Advance(Lifetimes.RefreshIdle);

        AssertInactive(await Introspect(RefreshValue));
    }

    [Fact]
    public async Task Unknown_refresh_token_is_inactive() =>
        AssertInactive(await Introspect(RefreshValue));

    private sealed class FakeValidator : IAccessTokenValidator
    {
        public VerifiedAccessToken? Result { get; set; }

        public (Guid TenantId, string Token)? Called { get; private set; }

        public ValueTask<VerifiedAccessToken?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken)
        {
            Called = (tenantId, token);
            return ValueTask.FromResult(Result);
        }
    }
}
