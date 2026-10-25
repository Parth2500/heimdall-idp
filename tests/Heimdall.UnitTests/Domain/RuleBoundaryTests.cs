using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Consents;
using Heimdall.Domain.Keys;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Domain;

/// <summary>
/// Rules that mutation testing (Stryker.NET, issue #13) showed were not checked by any test: guards that could be
/// removed, and boundaries that could move by one with no test failing.
/// </summary>
public class RuleBoundaryTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Callback = "https://app.example.com/callback";
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Id = Guid.CreateVersion7();
    private static readonly TokenLifetimes Lifetimes = new(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(30));

    private static Client NewClient(
        string clientId = "web-app",
        ClientType type = ClientType.Confidential,
        GrantType[]? grants = null,
        string[]? audiences = null,
        ClientTokenOverrides? overrides = null) =>
        Client.Create(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            clientId,
            "Web app",
            type,
            grants ?? [GrantType.AuthorizationCode],
            ["openid"],
            [Callback],
            requireConsent: false,
            overrides,
            Now,
            audiences);

    // ---- Empty IDs: an entity must never belong to no tenant, no user, or no client.

    public static TheoryData<string, Action> EmptyIdFactories() => new()
    {
        { "client id", () => Client.Create(Guid.Empty, Id, "c", "C", ClientType.Public, [GrantType.AuthorizationCode], [], [Callback], false, null, Now) },
        { "client tenant", () => Client.Create(Id, Guid.Empty, "c", "C", ClientType.Public, [GrantType.AuthorizationCode], [], [Callback], false, null, Now) },
        { "session tenant", () => Session.Start(TokenHash.Compute("s"), "sid-for-tests-00000000", Guid.Empty, Id, TimeSpan.FromHours(1), Now) },
        { "session user", () => Session.Start(TokenHash.Compute("s"), "sid-for-tests-00000000", Id, Guid.Empty, TimeSpan.FromHours(1), Now) },
        { "user id", () => User.Create(Guid.Empty, Id, "a@example.com", "hash", Now) },
        { "user tenant", () => User.Create(Id, Guid.Empty, "a@example.com", "hash", Now) },
        { "code id", () => AuthorizationCode.Create(Guid.Empty, Id, Id, Id, TokenHash.Compute("c"), Callback, "openid", Challenge, null, Now, Now, "sid-for-tests-00000000") },
        { "code tenant", () => AuthorizationCode.Create(Id, Guid.Empty, Id, Id, TokenHash.Compute("c"), Callback, "openid", Challenge, null, Now, Now, "sid-for-tests-00000000") },
        { "code client", () => AuthorizationCode.Create(Id, Id, Guid.Empty, Id, TokenHash.Compute("c"), Callback, "openid", Challenge, null, Now, Now, "sid-for-tests-00000000") },
        { "code user", () => AuthorizationCode.Create(Id, Id, Id, Guid.Empty, TokenHash.Compute("c"), Callback, "openid", Challenge, null, Now, Now, "sid-for-tests-00000000") },
        { "request id", () => AuthorizationRequest.Create(Guid.Empty, Id, Id, Callback, "openid", null, null, Challenge, false, null, Now) },
        { "request tenant", () => AuthorizationRequest.Create(Id, Guid.Empty, Id, Callback, "openid", null, null, Challenge, false, null, Now) },
        { "request client", () => AuthorizationRequest.Create(Id, Id, Guid.Empty, Callback, "openid", null, null, Challenge, false, null, Now) },
        { "family id", () => TokenFamily.Start(Guid.Empty, Id, Id, Id, Id, "openid", Lifetimes, Now) },
        { "family tenant", () => TokenFamily.Start(Id, Guid.Empty, Id, Id, Id, "openid", Lifetimes, Now) },
        { "family client", () => TokenFamily.Start(Id, Id, Guid.Empty, Id, Id, "openid", Lifetimes, Now) },
        { "family user", () => TokenFamily.Start(Id, Id, Id, Guid.Empty, Id, "openid", Lifetimes, Now) },
        { "family source code", () => TokenFamily.Start(Id, Id, Id, Id, Guid.Empty, "openid", Lifetimes, Now) },
        { "refresh id", () => RefreshToken.Create(Guid.Empty, Id, Id, TokenHash.Compute("r"), Now) },
        { "refresh tenant", () => RefreshToken.Create(Id, Guid.Empty, Id, TokenHash.Compute("r"), Now) },
        { "refresh family", () => RefreshToken.Create(Id, Id, Guid.Empty, TokenHash.Compute("r"), Now) },
        { "consent id", () => Consent.Grant(Guid.Empty, Id, Id, Id, ["openid"], Now) },
        { "consent tenant", () => Consent.Grant(Id, Guid.Empty, Id, Id, ["openid"], Now) },
        { "consent user", () => Consent.Grant(Id, Id, Guid.Empty, Id, ["openid"], Now) },
        { "consent client", () => Consent.Grant(Id, Id, Id, Guid.Empty, ["openid"], Now) },
        { "key id", () => SigningKey.Create(Guid.Empty, Id, "kid", "{}", "file:k", TimeSpan.FromMinutes(1), Now) },
        { "key tenant", () => SigningKey.Create(Id, Guid.Empty, "kid", "{}", "file:k", TimeSpan.FromMinutes(1), Now) },
    };

    [Theory]
    [MemberData(nameof(EmptyIdFactories))]
    public void An_empty_id_is_refused(string field, Action create)
    {
        Assert.False(string.IsNullOrEmpty(field));
        Assert.Throws<DomainException>(create);
    }

    [Fact]
    public void Used_and_redeemed_need_a_real_successor()
    {
        var token = RefreshToken.Create(Id, Id, Id, TokenHash.Compute("r"), Now);
        var code = AuthorizationCode.Create(Id, Id, Id, Id, TokenHash.Compute("c"), Callback, "openid", Challenge, null, Now, Now, "sid-for-tests-00000000");
        var request = AuthorizationRequest.Create(Id, Id, Id, Callback, "openid", null, null, Challenge, false, null, Now);

        Assert.Throws<DomainException>(() => token.Use(Guid.Empty, Now));
        Assert.Throws<DomainException>(() => code.Redeem(Guid.Empty, Now));
        Assert.Throws<DomainException>(() => request.DecideConsent(Guid.Empty, approved: true));
    }

    // ---- Client registration rules (D17, RFC 9700).

    [Theory]
    [InlineData("web app")]
    [InlineData("web\tapp")]
    public void Client_id_with_white_space_is_refused(string clientId)
    {
        Assert.Throws<DomainException>(() => NewClient(clientId: clientId));
    }

    [Fact]
    public void Client_needs_a_grant_type()
    {
        Assert.Throws<DomainException>(() => NewClient(grants: []));
    }

    [Fact]
    public void Public_client_cannot_use_client_credentials()
    {
        Assert.Throws<DomainException>(() =>
            NewClient(type: ClientType.Public, grants: [GrantType.ClientCredentials], audiences: ["https://api.example.com"]));
    }

    [Fact]
    public void Refresh_needs_the_authorization_code_grant()
    {
        Assert.Throws<DomainException>(() =>
            NewClient(grants: [GrantType.ClientCredentials, GrantType.RefreshToken], audiences: ["https://api.example.com"]));
    }

    [Theory]
    [InlineData("https://app.example.com/*")]
    [InlineData("https://*.example.com/callback")]
    public void Redirect_uri_with_a_wildcard_is_refused(string uri)
    {
        Assert.Throws<DomainException>(() => Client.Create(
            Id, Id, "c", "C", ClientType.Public, [GrantType.AuthorizationCode], [], [uri], false, null, Now));
    }

    [Theory]
    [InlineData("http://localhost:5000")]
    [InlineData("http://127.0.0.1:5000")]
    public void Plain_http_audience_is_allowed_for_loopback_only(string loopback)
    {
        Assert.Equal([loopback], NewClient(audiences: [loopback]).AllowedAudiences);
        Assert.Throws<DomainException>(() => NewClient(audiences: ["http://api.example.com"]));
    }

    [Fact]
    public void Client_lifetimes_use_each_override_and_allow_idle_equal_to_absolute()
    {
        var tenant = TenantSettings.Default;
        var overrides = new ClientTokenOverrides(TimeSpan.FromMinutes(2), TimeSpan.FromDays(3), TimeSpan.FromDays(3));

        var lifetimes = NewClient(overrides: overrides).ResolveLifetimes(tenant);

        Assert.Equal(TimeSpan.FromMinutes(2), lifetimes.AccessToken);
        Assert.Equal(TimeSpan.FromDays(3), lifetimes.RefreshIdle);
        Assert.Equal(TimeSpan.FromDays(3), lifetimes.RefreshAbsolute);
    }

    [Fact]
    public void Updated_overrides_apply_to_the_next_resolution()
    {
        var client = NewClient();
        client.UpdateTokenOverrides(new ClientTokenOverrides(TimeSpan.FromMinutes(1), null, null));

        Assert.Equal(TimeSpan.FromMinutes(1), client.ResolveLifetimes(TenantSettings.Default).AccessToken);
    }

    [Fact]
    public void Tenant_settings_allow_idle_equal_to_absolute()
    {
        var settings = new TenantSettings(TimeSpan.FromHours(1), TimeSpan.FromHours(1), TimeSpan.FromMinutes(5), TimeSpan.FromDays(1), TimeSpan.FromDays(1));

        Assert.Equal(settings.SessionIdle, settings.SessionAbsolute);
        Assert.Equal(settings.RefreshIdle, settings.RefreshAbsolute);
    }

    // ---- Authorization requests.

    [Fact]
    public void State_and_nonce_of_exactly_the_maximum_length_are_accepted()
    {
        var max = new string('s', AuthorizationRequest.MaxClientValueLength);

        var request = AuthorizationRequest.Create(Id, Id, Id, Callback, "openid", max, max, Challenge, false, null, Now);

        Assert.Equal(max, request.State);
        Assert.Equal(max, request.Nonce);
        Assert.Throws<DomainException>(() => AuthorizationRequest.Create(Id, Id, Id, Callback, "openid", null, max + "n", Challenge, false, null, Now));
    }

    [Fact]
    public void Max_age_of_zero_is_allowed_and_a_negative_one_is_refused()
    {
        Assert.Equal(TimeSpan.Zero, AuthorizationRequest.Create(Id, Id, Id, Callback, "openid", null, null, Challenge, false, TimeSpan.Zero, Now).MaxAge);
        Assert.Throws<DomainException>(() =>
            AuthorizationRequest.Create(Id, Id, Id, Callback, "openid", null, null, Challenge, false, TimeSpan.FromSeconds(-1), Now));
    }

    [Fact]
    public void Empty_state_and_nonce_are_stored_as_absent()
    {
        var request = AuthorizationRequest.Create(Id, Id, Id, Callback, "openid", string.Empty, string.Empty, Challenge, false, null, Now);

        Assert.Null(request.State);
        Assert.Null(request.Nonce);
    }

    // ---- Sessions.

    [Fact]
    public void Session_created_at_the_same_instant_as_a_password_change_is_valid()
    {
        var user = User.Create(Id, Id, "a@example.com", "hash", Now);
        var session = Session.Start(TokenHash.Compute("s"), "sid-for-tests-00000000", Id, user.Id, TimeSpan.FromHours(12), Now);

        Assert.True(session.IsValid(Id, user, TimeSpan.FromMinutes(30), Now));

        user.ChangePassword("new-hash", Now.AddTicks(1));
        Assert.False(session.IsValid(Id, user, TimeSpan.FromMinutes(30), Now.AddTicks(1)));
    }

    [Fact]
    public void Session_ends_exactly_at_the_idle_limit_and_a_second_revoke_keeps_the_first_time()
    {
        var user = User.Create(Id, Id, "a@example.com", "hash", Now.AddDays(-1));
        var session = Session.Start(TokenHash.Compute("s"), "sid-for-tests-00000000", Id, user.Id, TimeSpan.FromHours(12), Now);
        var idle = TimeSpan.FromMinutes(30);

        Assert.True(session.IsValid(Id, user, idle, Now + idle - TimeSpan.FromTicks(1)));
        Assert.False(session.IsValid(Id, user, idle, Now + idle));

        session.Revoke(Now.AddMinutes(1));
        session.Revoke(Now.AddMinutes(2));
        Assert.Equal(Now.AddMinutes(1), session.RevokedAt);
    }

    // ---- Token families and hashes.

    [Fact]
    public void Family_is_inactive_exactly_at_its_absolute_limit()
    {
        var shortLived = new TokenLifetimes(TimeSpan.FromMinutes(5), TimeSpan.FromDays(1), TimeSpan.FromDays(1));
        var family = TokenFamily.Start(Id, Id, Id, Id, Id, "openid", shortLived, Now);

        Assert.True(family.IsActive(Now + TimeSpan.FromDays(1) - TimeSpan.FromTicks(1)));
        Assert.False(family.IsActive(Now + TimeSpan.FromDays(1)));
        Assert.Throws<DomainException>(() => family.ExtendIdle(TimeSpan.FromDays(1), Now + TimeSpan.FromDays(1)));
    }

    [Fact]
    public void A_default_hash_equals_no_real_hash()
    {
        var real = TokenHash.Compute("secret");

        Assert.False(default(TokenHash).Equals(real));
        Assert.False(real.Equals(default(TokenHash)));
        Assert.False(default(TokenHash).Equals(default(TokenHash)));
        Assert.Empty(default(TokenHash).ToArray());
        Assert.Equal(0, default(TokenHash).GetHashCode());
    }

    [Fact]
    public void Hash_copy_and_hash_code_come_from_the_bytes()
    {
        var hash = TokenHash.Compute("secret");
        var copy = hash.ToArray();
        copy[0] ^= 0xFF;

        Assert.Equal(TokenHash.FromBytes(hash.ToArray()), hash);
        Assert.NotEqual(copy, hash.ToArray());
        Assert.Equal(TokenHash.Compute("secret").GetHashCode(), hash.GetHashCode());
    }

    // ---- Consent.

    [Fact]
    public void Approve_needs_a_scope_and_a_second_revoke_keeps_the_first_time()
    {
        var consent = Consent.Grant(Id, Id, Id, Id, ["openid"], Now);

        Assert.Throws<DomainException>(() => consent.Approve([], Now));

        consent.Revoke(Now.AddMinutes(1));
        consent.Revoke(Now.AddMinutes(2));
        Assert.Equal(Now.AddMinutes(1), consent.RevokedAt);
    }

    // ---- Signing keys.

    [Fact]
    public void Kid_with_white_space_is_refused()
    {
        Assert.Throws<DomainException>(() => SigningKey.Create(Id, Id, "my kid", "{}", "file:k", TimeSpan.FromMinutes(1), Now));
    }

    [Fact]
    public void Only_a_pending_key_can_be_activated_and_only_an_active_key_retired()
    {
        var first = SigningKey.Create(Guid.CreateVersion7(), Id, "k1", "{}", "file:k1", TimeSpan.FromMinutes(1), Now);
        var second = SigningKey.Create(Guid.CreateVersion7(), Id, "k2", "{}", "file:k2", TimeSpan.FromMinutes(1), Now);
        var later = Now.AddMinutes(1);

        // A pending key cannot be the current key of a rotation. The check runs before the next key changes, so a
        // refused rotation leaves no half-done state.
        Assert.Throws<DomainException>(() => SigningKeyRotation.Rotate(first, second, TimeSpan.FromMinutes(5), TimeSpan.Zero, later));
        Assert.Equal(SigningKeyStatus.Pending, second.Status);

        SigningKeyRotation.ActivateFirst(first, later);
        Assert.Throws<DomainException>(() => SigningKeyRotation.ActivateFirst(first, later));
    }

    [Fact]
    public void Rotation_refuses_a_negative_clock_skew_and_allows_zero()
    {
        var current = SigningKey.Create(Guid.CreateVersion7(), Id, "k1", "{}", "file:k1", TimeSpan.FromMinutes(1), Now);
        var next = SigningKey.Create(Guid.CreateVersion7(), Id, "k2", "{}", "file:k2", TimeSpan.FromMinutes(1), Now);
        var later = Now.AddMinutes(1);
        SigningKeyRotation.ActivateFirst(current, later);

        Assert.Throws<DomainException>(() => SigningKeyRotation.Rotate(current, next, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(-1), later));
        Assert.Equal(SigningKeyStatus.Pending, next.Status);

        SigningKeyRotation.Rotate(current, next, TimeSpan.FromMinutes(5), TimeSpan.Zero, later);
        Assert.Equal(later + TimeSpan.FromMinutes(5), current.RemoveAfter);
    }

    [Fact]
    public void Emergency_removal_keeps_the_first_retirement_time()
    {
        var key = SigningKey.Create(Guid.CreateVersion7(), Id, "k1", "{}", "file:k1", TimeSpan.FromMinutes(1), Now);
        SigningKeyRotation.ActivateFirst(key, Now.AddMinutes(1));

        key.RemoveNow(Now.AddMinutes(2));
        key.RemoveNow(Now.AddMinutes(3));

        Assert.Equal(Now.AddMinutes(2), key.RetiredAt);
        Assert.False(key.IsPublished(Now.AddMinutes(3)));
    }

    // ---- Zero durations, blank values, and settings changes.

    public static TheoryData<string, Action> ZeroDurations() => new()
    {
        { "jwks cache lifetime", () => SigningKey.Create(Id, Id, "kid", "{}", "file:k", TimeSpan.Zero, Now) },
        { "session lifetime", () => Session.Start(TokenHash.Compute("s"), "sid-for-tests-00000000", Id, Id, TimeSpan.Zero, Now) },
        { "family idle extension", () => TokenFamily.Start(Id, Id, Id, Id, Id, "openid", Lifetimes, Now).ExtendIdle(TimeSpan.Zero, Now) },
        { "rotation token lifetime", () => SigningKeyRotation.Rotate(
            SigningKey.Create(Guid.CreateVersion7(), Id, "k1", "{}", "file:k1", TimeSpan.FromMinutes(1), Now),
            SigningKey.Create(Guid.CreateVersion7(), Id, "k2", "{}", "file:k2", TimeSpan.FromMinutes(1), Now),
            TimeSpan.Zero,
            TimeSpan.Zero,
            Now.AddMinutes(1)) },
    };

    [Theory]
    [MemberData(nameof(ZeroDurations))]
    public void A_zero_duration_is_refused(string setting, Action create)
    {
        Assert.False(string.IsNullOrEmpty(setting));
        Assert.Throws<DomainException>(create);
    }

    [Fact]
    public void Audit_event_needs_an_id_and_userinfo_audience_must_not_be_blank()
    {
        Assert.Throws<DomainException>(() => Heimdall.Domain.Audit.AuditEvent.Record(Guid.Empty, Id, "test.event", "corr", Now));
        Assert.Throws<DomainException>(() => NewClient().ResolveUserAudience(null, " "));
    }

    [Fact]
    public void Scope_with_white_space_is_refused()
    {
        Assert.Throws<DomainException>(() => Client.Create(
            Id, Id, "c", "C", ClientType.Public, [GrantType.AuthorizationCode], ["open id"], [Callback], false, null, Now));
    }

    [Fact]
    public void Updated_tenant_settings_replace_the_old_ones()
    {
        var tenant = Tenant.Create(Id, "acme.example.com", "Acme", TenantSettings.Default, Now);
        var settings = new TenantSettings(TimeSpan.FromMinutes(10), TimeSpan.FromHours(2), TimeSpan.FromMinutes(5), TimeSpan.FromDays(1), TimeSpan.FromDays(2));

        tenant.UpdateSettings(settings);

        Assert.Same(settings, tenant.Settings);
    }

    // ---- Sign-in throttle.

    [Fact]
    public void Zero_free_failures_is_a_valid_setting()
    {
        Assert.Equal(TimeSpan.FromSeconds(1), LoginThrottle.DelayAfter(1, 0, TimeSpan.FromMinutes(15)));
    }
}
