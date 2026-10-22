using System.Net;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class RefreshTokenGrantTests
{
    private const string Issuer = "https://acme.example.com";
    private const string UserInfoAudience = Issuer + "/oauth/v1/userinfo";
    private const string Callback = "https://app.example.com/callback";
    private const string FamilyScope = "openid profile offline_access";
    private const string Token = "first-refresh-token";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryTokenStore _tokens = new();
    private readonly InMemoryUserStore _users = new();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly RecordingTokenSigner _signer = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly RecordingSecurityAlerts _alerts = new();
    private readonly RefreshTokenGrant _grant;
    private readonly Client _spa;
    private readonly User _user;
    private readonly TokenFamily _family;
    private readonly RefreshToken _first;

    public RefreshTokenGrantTests()
    {
        _grant = new RefreshTokenGrant(new ClientAuthenticator(_clients, _time), _tokens, _users, _signer, _audit, _alerts, _time);
        _spa = AddPublicClient("spa");
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", "hash", Now);
        _users.Add(_user);
        (_family, _first) = StartFamily(_spa, Token);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private static TimeSpan RefreshIdle => TenantSettings.Default.RefreshIdle;

    private Client AddPublicClient(string clientId, GrantType[]? grants = null, string[]? audiences = null)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            clientId,
            "Single-page app",
            ClientType.Public,
            grants ?? [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "profile", "offline_access"],
            [Callback],
            requireConsent: false,
            overrides: null,
            Now,
            audiences);
        client.Approve();
        _clients.Add(client);
        return client;
    }

    private (TokenFamily Family, RefreshToken Token) StartFamily(Client client, string token, Guid? tenantId = null)
    {
        var tenant = tenantId ?? _tenant.Id;
        var family = TokenFamily.Start(
            Guid.CreateVersion7(), tenant, client.Id, _user.Id, Guid.CreateVersion7(), FamilyScope,
            client.ResolveLifetimes(_tenant.Settings), _time.GetUtcNow());
        var refresh = RefreshToken.Create(Guid.CreateVersion7(), tenant, family.Id, TokenHash.Compute(token), _time.GetUtcNow());
        _tokens.Families.Add(family);
        _tokens.RefreshTokens.Add(refresh);
        return (family, refresh);
    }

    private Task<Result<TokenResponse>> Refresh(
        string? token = Token,
        string? clientId = "spa",
        string? scope = null,
        string? resource = null,
        string? secret = null) =>
        _grant.HandleAsync(Context, new RefreshTokenRequest(clientId, secret, token, scope, resource), CancellationToken.None);

    private AuditEvent Rejected(Result<TokenResponse> result, string error, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(error, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
        var rejected = _audit.Events.Last(e => e.Type == AuditEventTypes.TokenRejected);
        Assert.Equal("refresh_token", rejected.Data["grant_type"]);
        Assert.Equal(error, rejected.Data["error"]);
        Assert.Equal(reason, rejected.Data["reason"]);
        return rejected;
    }

    [Fact]
    public async Task Rotation_returns_a_new_refresh_token_and_marks_the_old_one_used()
    {
        _time.Advance(TimeSpan.FromHours(1));
        var now = _time.GetUtcNow();

        var result = await Refresh();

        Assert.True(result.IsSuccess);
        var response = result.Value;
        Assert.Equal("Bearer", response.TokenType);
        Assert.Equal(300, response.ExpiresIn);
        Assert.Equal(FamilyScope, response.Scope);
        Assert.Null(response.IdToken);
        Assert.Equal(43, response.RefreshToken!.Length);

        var next = Assert.Single(_tokens.RefreshTokens, t => t.Hash == TokenHash.Compute(response.RefreshToken));
        Assert.Equal(_family.Id, next.FamilyId);
        Assert.Equal(_tenant.Id, next.TenantId);
        Assert.Equal(now, next.CreatedAt);
        Assert.Null(next.UsedAt);
        Assert.Equal(now, _first.UsedAt);
        Assert.Equal(next.Id, _first.ReplacedById);
        Assert.Equal(now + RefreshIdle, _family.IdleExpiresAt);
        Assert.Equal(1, _tokens.Commits);

        var (tenantId, access) = Assert.Single(_signer.Signed);
        Assert.Equal(_tenant.Id, tenantId);
        Assert.Equal(Issuer, access.Issuer);
        Assert.Equal(_user.Id.ToString(), access.Subject);
        Assert.Equal(UserInfoAudience, access.Audience);
        Assert.Equal("spa", access.ClientId);
        Assert.Equal(["openid", "profile", "offline_access"], access.Scopes);
        Assert.Equal(now, access.IssuedAt);
        Assert.Equal(now.AddMinutes(5), access.ExpiresAt);
        Assert.Matches("^[0-9a-f]{32}$", access.JwtId);

        var rotated = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.RefreshRotated, rotated.Type);
        Assert.Equal(_spa.Id, rotated.ClientPk);
        Assert.Equal(_user.Id, rotated.SubjectUserId);
        Assert.Equal(_family.Id, rotated.FamilyId);
        Assert.Equal("corr-1", rotated.CorrelationId);
        Assert.Equal(FamilyScope, rotated.Data["scope"]);
        Assert.Equal(UserInfoAudience, rotated.Data["aud"]);
    }

    [Fact]
    public async Task The_new_refresh_token_works_once()
    {
        var next = (await Refresh()).Value.RefreshToken;

        Assert.True((await Refresh(next)).IsSuccess);
    }

    [Fact]
    public async Task Narrower_scope_is_allowed()
    {
        var result = await Refresh(scope: "openid");

        Assert.Equal("openid", result.Value.Scope);
        Assert.Equal(["openid"], _signer.Signed[0].Claims.Scopes);
        Assert.Equal("openid", _audit.Events[0].Data["scope"]);
    }

    [Fact]
    public async Task Wider_scope_is_refused_and_the_token_stays_usable()
    {
        Rejected(await Refresh(scope: "openid email"), OAuthError.InvalidScopeCode, "scope wider than the original grant");

        Assert.Null(_first.UsedAt);
        Assert.Equal(1, _tokens.Rollbacks);
        Assert.Null(_family.RevokedAt);
        Assert.True((await Refresh()).IsSuccess);
    }

    [Fact]
    public async Task Malformed_scope_is_invalid_scope()
    {
        Rejected(await Refresh(scope: "openid \"x\""), OAuthError.InvalidScopeCode, "malformed scope");
        Assert.Null(_first.UsedAt);
    }

    [Fact]
    public async Task Disabled_user_ends_the_family()
    {
        _user.Disable();

        Rejected(await Refresh(), OAuthError.InvalidGrantCode, "user disabled");

        Assert.Equal(FamilyRevocationReason.UserDisabled, _family.RevocationReason);
        Assert.Equal(Now, _family.RevokedAt);
        var revoked = Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.FamilyRevoked);
        Assert.Equal("user_disabled", revoked.Data["reason"]);
        Assert.Equal(_spa.Id, revoked.ClientPk);
        Assert.Equal(_user.Id, revoked.SubjectUserId);
        Assert.Equal(_family.Id, revoked.FamilyId);
        Assert.Empty(_signer.Signed);
        Assert.Empty(_alerts.Raised);
    }

    [Fact]
    public async Task Deleted_user_ends_the_family()
    {
        _users.Users.Clear();

        Rejected(await Refresh(), OAuthError.InvalidGrantCode, "user disabled");
        Assert.NotNull(_family.RevokedAt);
    }

    [Fact]
    public async Task Disabled_user_with_an_already_revoked_family_writes_no_second_revocation()
    {
        // Another server revoked the family between the rotation and the revocation.
        _user.Disable();
        var revokeFirst = new RevokingTokenStore(_tokens, _family);
        var grant = new RefreshTokenGrant(new ClientAuthenticator(_clients, _time), revokeFirst, _users, _signer, _audit, _alerts, _time);

        await grant.HandleAsync(Context, new RefreshTokenRequest("spa", null, Token, null, null), CancellationToken.None);

        Assert.DoesNotContain(_audit.Events, e => e.Type == AuditEventTypes.FamilyRevoked);
    }

    [Fact]
    public async Task Reused_token_revokes_the_whole_family_and_raises_an_alert()
    {
        var next = (await Refresh()).Value.RefreshToken;
        _time.Advance(TimeSpan.FromSeconds(10));

        var rejected = Rejected(await Refresh(), OAuthError.InvalidGrantCode, "refresh token reused");

        Assert.Equal("spa", rejected.Data["client_id"]);
        Assert.Equal(Now.AddSeconds(10), _family.RevokedAt);
        Assert.Equal(FamilyRevocationReason.ReuseDetected, _family.RevocationReason);

        var reuse = Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.RefreshReuseDetected);
        Assert.Equal(_spa.Id, reuse.ClientPk);
        Assert.Equal(_user.Id, reuse.SubjectUserId);
        Assert.Equal(_family.Id, reuse.FamilyId);
        Assert.Equal("spa", reuse.Data["client_id"]);
        Assert.Equal("yes", reuse.Data["family_revoked"]);

        var revoked = Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.FamilyRevoked);
        Assert.Equal("reuse_detected", revoked.Data["reason"]);
        Assert.Equal(_family.Id, revoked.FamilyId);

        var alert = Assert.Single(_alerts.Raised);
        Assert.Equal(AuditEventTypes.RefreshReuseDetected, alert.Type);
        Assert.Equal(_tenant.Id, alert.TenantId);
        Assert.Equal("yes", alert.Data["family_revoked"]);

        // No grace window: the newest token of the family stops working too.
        Rejected(await Refresh(next), OAuthError.InvalidGrantCode, "family revoked");
    }

    [Fact]
    public async Task Reuse_by_another_client_still_revokes_the_family()
    {
        await Refresh();
        AddPublicClient("thief");

        var rejected = Rejected(await Refresh(clientId: "thief"), OAuthError.InvalidGrantCode, "refresh token reused");

        Assert.Equal("thief", rejected.Data["client_id"]);
        Assert.NotNull(_family.RevokedAt);
        var reuse = Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.RefreshReuseDetected);
        Assert.Equal(_spa.Id, reuse.ClientPk);
        Assert.Equal("thief", reuse.Data["client_id"]);
    }

    [Fact]
    public async Task Second_reuse_finds_the_family_already_revoked()
    {
        await Refresh();
        await Refresh();
        var auditBefore = _audit.Events.Count;

        await Refresh();

        var events = _audit.Events.Skip(auditBefore).ToList();
        Assert.Equal("already revoked", Assert.Single(events, e => e.Type == AuditEventTypes.RefreshReuseDetected).Data["family_revoked"]);
        Assert.DoesNotContain(events, e => e.Type == AuditEventTypes.FamilyRevoked);
        Assert.Equal(2, _alerts.Raised.Count);
    }

    [Fact]
    public async Task Unused_token_of_another_client_is_refused_and_not_burned()
    {
        AddPublicClient("other");

        Rejected(await Refresh(clientId: "other"), OAuthError.InvalidGrantCode, "refresh token of another client");

        Assert.Null(_first.UsedAt);
        Assert.Null(_family.RevokedAt);
        Assert.True((await Refresh()).IsSuccess);
    }

    [Fact]
    public async Task Token_of_a_revoked_family_is_refused()
    {
        _family.Revoke(FamilyRevocationReason.Admin, Now);

        Rejected(await Refresh(), OAuthError.InvalidGrantCode, "family revoked");
        Assert.Empty(_alerts.Raised);
    }

    [Fact]
    public async Task Token_works_until_one_tick_before_the_idle_limit()
    {
        _time.Advance(RefreshIdle - TimeSpan.FromTicks(1));

        Assert.True((await Refresh()).IsSuccess);
    }

    [Fact]
    public async Task Token_after_the_idle_limit_is_refused()
    {
        _time.Advance(RefreshIdle);

        Rejected(await Refresh(), OAuthError.InvalidGrantCode, "family expired");
        Assert.Null(_first.UsedAt);
    }

    [Fact]
    public async Task Unknown_token_is_invalid_grant()
    {
        Rejected(await Refresh("no-such-token"), OAuthError.InvalidGrantCode, "unknown refresh token");
    }

    [Fact]
    public async Task Token_of_another_tenant_is_unknown()
    {
        StartFamily(_spa, "other-tenant-token", Guid.CreateVersion7());

        Rejected(await Refresh("other-tenant-token"), OAuthError.InvalidGrantCode, "unknown refresh token");
    }

    [Fact]
    public async Task Token_without_its_family_is_invalid_grant()
    {
        var orphan = RefreshToken.Create(Guid.CreateVersion7(), _tenant.Id, Guid.CreateVersion7(), TokenHash.Compute("orphan"), Now);
        _tokens.RefreshTokens.Add(orphan);

        Rejected(await Refresh("orphan"), OAuthError.InvalidGrantCode, "family missing");
    }

    [Fact]
    public async Task Suspended_tenant_rotates_nothing()
    {
        _tenant.Suspend();

        Rejected(await Refresh(), OAuthError.InvalidClientCode, "tenant suspended");
        Assert.Null(_first.UsedAt);
    }

    [Fact]
    public async Task Unauthenticated_client_rotates_nothing()
    {
        Rejected(await Refresh(clientId: "no-such-client"), OAuthError.InvalidClientCode, "unknown client");
        Assert.Null(_first.UsedAt);
    }

    [Fact]
    public async Task Client_without_the_grant_is_unauthorized_client()
    {
        AddPublicClient("code-only", grants: [GrantType.AuthorizationCode]);

        Rejected(await Refresh(clientId: "code-only"), OAuthError.UnauthorizedClientCode, "refresh_token not allowed");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Missing_refresh_token_is_invalid_request(string? token)
    {
        Rejected(await Refresh(token), OAuthError.InvalidRequestCode, "refresh_token missing");
    }

    [Fact]
    public async Task Resource_that_is_not_allowed_is_invalid_target()
    {
        Rejected(await Refresh(resource: "https://evil.example.com"), OAuthError.InvalidTargetCode, "resource missing or not allowed");
        Assert.Null(_first.UsedAt);
    }

    [Fact]
    public async Task Requested_resource_becomes_the_audience()
    {
        var client = AddPublicClient("api-client", audiences: ["https://api.example.com"]);
        StartFamily(client, "api-token");

        await Refresh("api-token", clientId: "api-client", resource: "https://api.example.com");

        Assert.Equal("https://api.example.com", _signer.Signed[0].Claims.Audience);
    }

    [Fact]
    public async Task Failed_signing_rolls_back_and_leaves_the_token_usable()
    {
        _signer.Unavailable = true;

        await Assert.ThrowsAsync<SigningKeyUnavailableException>(() => Refresh());

        Assert.Null(_first.UsedAt);
        Assert.Single(_tokens.RefreshTokens);
        Assert.Equal(1, _tokens.Rollbacks);
        Assert.Empty(_audit.Events);

        _signer.Unavailable = false;
        Assert.True((await Refresh()).IsSuccess);
    }

    [Theory]
    [InlineData(128, 128)]
    [InlineData(129, 128)]
    [InlineData(5000, 128)]
    public async Task Rejection_audit_caps_the_client_id(int length, int audited)
    {
        await Refresh(clientId: new string('x', length));

        Assert.Equal(audited, _audit.Events[0].Data["client_id"].Length);
    }

    [Fact]
    public async Task Missing_client_id_is_audited_as_empty()
    {
        await Refresh(clientId: null);

        Assert.Equal(string.Empty, _audit.Events[0].Data["client_id"]);
    }

    /// <summary>Revokes the family when the grant reads it, as if another server revoked it at that moment.</summary>
    private sealed class RevokingTokenStore(InMemoryTokenStore inner, TokenFamily family) : ITokenStore
    {
        public Task<IGrantTransaction> BeginTransactionAsync(CancellationToken cancellationToken) => inner.BeginTransactionAsync(cancellationToken);

        public Task<AuthorizationCode?> RedeemCodeAsync(CodeRedemption redemption, CancellationToken cancellationToken) =>
            inner.RedeemCodeAsync(redemption, cancellationToken);

        public Task<AuthorizationCode?> FindCodeAsync(Guid tenantId, TokenHash codeHash, CancellationToken cancellationToken) =>
            inner.FindCodeAsync(tenantId, codeHash, cancellationToken);

        public void AddFamily(TokenFamily family) => inner.AddFamily(family);

        public void AddRefreshToken(RefreshToken token) => inner.AddRefreshToken(token);

        public Task SaveChangesAsync(CancellationToken cancellationToken) => inner.SaveChangesAsync(cancellationToken);

        public Task<RefreshToken?> UseRefreshTokenAsync(RefreshRotation rotation, CancellationToken cancellationToken) =>
            inner.UseRefreshTokenAsync(rotation, cancellationToken);

        public Task<RefreshToken?> FindRefreshTokenAsync(Guid tenantId, TokenHash tokenHash, CancellationToken cancellationToken) =>
            inner.FindRefreshTokenAsync(tenantId, tokenHash, cancellationToken);

        public async Task<TokenFamily?> FindFamilyAsync(Guid tenantId, Guid familyId, CancellationToken cancellationToken)
        {
            var found = await inner.FindFamilyAsync(tenantId, familyId, cancellationToken);
            // The other server's change commits on its own, so this transaction's rollback must not undo it.
            InMemoryTokenStore.Set(family, nameof(TokenFamily.RevokedAt), (DateTimeOffset?)DateTimeOffset.UnixEpoch);
            return found;
        }

        public Task CompleteRotationAsync(RefreshToken used, RefreshToken replacement, TimeSpan idleTimeout, DateTimeOffset now, CancellationToken cancellationToken) =>
            inner.CompleteRotationAsync(used, replacement, idleTimeout, now, cancellationToken);

        public Task<bool> RevokeFamilyAsync(Guid tenantId, Guid familyId, FamilyRevocationReason reason, DateTimeOffset now, CancellationToken cancellationToken) =>
            inner.RevokeFamilyAsync(tenantId, familyId, reason, now, cancellationToken);
    }
}
