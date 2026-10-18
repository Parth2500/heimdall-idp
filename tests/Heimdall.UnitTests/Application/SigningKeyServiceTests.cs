using Heimdall.Application.Common;
using Heimdall.Application.Keys;
using Heimdall.Application.Settings;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class SigningKeyServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly SigningKeyOptions Options = new()
    {
        JwksCacheLifetime = TimeSpan.FromMinutes(10),
        ServerCacheLifetime = TimeSpan.FromMinutes(1),
    };

    // The JWKS cache lifetime plus the server cache lifetime.
    private static readonly TimeSpan Wait = TimeSpan.FromMinutes(11);

    private readonly Guid _tenantId = Guid.CreateVersion7();
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemorySigningKeyStore _keys = new();
    private readonly RecordingSigningKeyCache _cache = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly SigningKeyService _service;

    public SigningKeyServiceTests()
    {
        _service = new SigningKeyService(
            new FakeKeyMaterialStore(),
            _keys,
            _cache,
            _audit,
            Options,
            new PlatformLimits(),
            _time);
    }

    private Task<SigningKey> Create() => _service.CreateKeyAsync(_tenantId, "corr-1", CancellationToken.None);

    private Task<SigningKey?> Activate() => _service.ActivateFirstKeyAsync(_tenantId, "corr-2", CancellationToken.None);

    [Fact]
    public async Task New_key_is_pending_and_waits_for_every_cache()
    {
        var key = await Create();

        Assert.Equal(SigningKeyStatus.Pending, key.Status);
        Assert.Equal(Now, key.PublishedAt);
        Assert.Equal(Wait, Options.PublishWait);
        Assert.Equal(Now + Wait, key.SigningFrom);
        Assert.Equal("fake:1", key.PrivateKeyRef);
        Assert.Same(key, Assert.Single(_keys.Keys));
    }

    [Fact]
    public async Task New_key_has_the_thumbprint_as_kid_and_a_public_jwk()
    {
        var key = await Create();

        var jwk = RsaPublicJwk.FromJson(key.PublicJwk);
        Assert.Equal(RsaPublicJwk.ComputeThumbprint("modulus1", "AQAB"), key.Kid);
        Assert.Equal(key.Kid, jwk.Kid);
        Assert.DoesNotContain("fake:1", key.PublicJwk, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Creation_is_audited_and_invalidates_the_cache()
    {
        var key = await Create();

        var created = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.KeyCreated, created.Type);
        Assert.Equal(_tenantId, created.TenantId);
        Assert.Equal("corr-1", created.CorrelationId);
        Assert.Equal(key.Kid, created.Data["kid"]);
        Assert.Equal([_tenantId], _cache.Invalidated);
    }

    [Fact]
    public async Task Key_is_not_activated_before_signing_from()
    {
        await Create();
        _time.Advance(Wait - TimeSpan.FromSeconds(1));

        var activated = await Activate();

        Assert.Null(activated);
        Assert.Equal(SigningKeyStatus.Pending, _keys.Keys[0].Status);
        Assert.Single(_audit.Events);
    }

    [Fact]
    public async Task Key_is_activated_at_signing_from_and_the_change_is_audited()
    {
        var key = await Create();
        _time.Advance(Wait);
        _cache.Invalidated.Clear();

        var activated = await Activate();

        Assert.Same(key, activated);
        Assert.Equal(SigningKeyStatus.Active, key.Status);
        Assert.Equal(AuditEventTypes.KeyActivated, _audit.Events[^1].Type);
        Assert.Equal("corr-2", _audit.Events[^1].CorrelationId);
        Assert.Equal([_tenantId], _cache.Invalidated);
    }

    [Fact]
    public async Task Nothing_changes_when_the_tenant_already_has_an_active_key()
    {
        var first = await Create();
        _time.Advance(Wait);
        await Activate();
        var second = await Create();
        _time.Advance(Wait);
        var auditCount = _audit.Events.Count;

        var activated = await Activate();

        Assert.Null(activated);
        Assert.Equal(SigningKeyStatus.Active, first.Status);
        Assert.Equal(SigningKeyStatus.Pending, second.Status);
        Assert.Equal(auditCount, _audit.Events.Count);
    }

    [Fact]
    public async Task Keys_of_another_tenant_are_not_activated()
    {
        await Create();
        _time.Advance(Wait);

        var activated = await _service.ActivateFirstKeyAsync(Guid.CreateVersion7(), "corr-3", CancellationToken.None);

        Assert.Null(activated);
        Assert.Equal(SigningKeyStatus.Pending, _keys.Keys[0].Status);
    }

    [Fact]
    public async Task Lost_activation_race_returns_null_and_writes_no_audit_event()
    {
        await Create();
        _time.Advance(Wait);
        _keys.LoseNextSave = true;
        var auditCount = _audit.Events.Count;
        _cache.Invalidated.Clear();

        var activated = await Activate();

        Assert.Null(activated);
        Assert.Equal(auditCount, _audit.Events.Count);
        Assert.Equal([_tenantId], _cache.Invalidated);
    }

    [Fact]
    public void Options_reject_zero_lifetimes()
    {
        var options = new SigningKeyOptions
        {
            JwksCacheLifetime = TimeSpan.Zero,
            ServerCacheLifetime = TimeSpan.FromSeconds(-1),
            ActivationCheckInterval = TimeSpan.Zero,
            ClockSkew = TimeSpan.FromSeconds(-1),
        };

        Assert.Equal(4, options.Validate().Count);
        Assert.Empty(new SigningKeyOptions().Validate());
    }

    [Fact]
    public void Rotation_interval_must_be_longer_than_the_publish_wait()
    {
        var options = new SigningKeyOptions { RotationInterval = TimeSpan.FromMinutes(11) };

        Assert.Single(options.Validate());
    }

    [Fact]
    public async Task Second_pending_key_is_refused()
    {
        await Create();

        await Assert.ThrowsAsync<ConcurrentUpdateException>(Create);
        Assert.Single(_keys.Keys);
    }

    private Task<KeyMaintenanceAction> Maintain() => _service.MaintainAsync(_tenantId, "corr-m", CancellationToken.None);

    /// <summary>A tenant with an active key that started to sign now.</summary>
    private async Task<SigningKey> ActiveKey()
    {
        Assert.Equal(KeyMaintenanceAction.Created, await Maintain());
        _time.Advance(Wait);
        Assert.Equal(KeyMaintenanceAction.Activated, await Maintain());
        return _keys.Keys.Single(k => k.Status == SigningKeyStatus.Active);
    }

    [Fact]
    public async Task Maintain_creates_then_activates_the_first_key()
    {
        Assert.Equal(KeyMaintenanceAction.Created, await Maintain());
        Assert.Equal(KeyMaintenanceAction.None, await Maintain());

        _time.Advance(Wait);

        Assert.Equal(KeyMaintenanceAction.Activated, await Maintain());
        Assert.Equal(SigningKeyStatus.Active, Assert.Single(_keys.Keys).Status);
    }

    [Fact]
    public async Task Maintain_creates_the_next_key_one_publish_wait_before_rotation()
    {
        await ActiveKey();

        _time.Advance(Options.RotationInterval - Wait - TimeSpan.FromSeconds(1));
        Assert.Equal(KeyMaintenanceAction.None, await Maintain());

        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(KeyMaintenanceAction.Created, await Maintain());
        var next = _keys.Keys.Single(k => k.Status == SigningKeyStatus.Pending);

        // The next key is ready exactly when rotation is due.
        Assert.Equal(_time.GetUtcNow() + Wait, next.SigningFrom);
    }

    [Fact]
    public async Task Rotation_activates_the_next_key_and_retires_the_old_one_with_an_overlap()
    {
        var old = await ActiveKey();
        _time.Advance(Options.RotationInterval - Wait);
        await Maintain();
        var next = _keys.Keys.Single(k => k.Status == SigningKeyStatus.Pending);
        _time.Advance(Wait - TimeSpan.FromSeconds(1));
        Assert.Equal(KeyMaintenanceAction.None, await Maintain());
        _time.Advance(TimeSpan.FromSeconds(1));
        var auditBefore = _audit.Events.Count;

        Assert.Equal(KeyMaintenanceAction.Rotated, await Maintain());

        var now = _time.GetUtcNow();
        Assert.Equal(SigningKeyStatus.Active, next.Status);
        Assert.Equal(SigningKeyStatus.Retired, old.Status);

        // 60 minutes (the platform's longest access token) plus 5 minutes of clock skew.
        Assert.Equal(now + TimeSpan.FromMinutes(65), old.RemoveAfter);
        Assert.True(old.IsPublished(now + TimeSpan.FromMinutes(64)));
        Assert.False(old.IsPublished(now + TimeSpan.FromMinutes(65)));
        Assert.Equal(
            [AuditEventTypes.KeyActivated, AuditEventTypes.KeyRetired],
            _audit.Events.Skip(auditBefore).Select(e => e.Type));
        Assert.Equal(old.Kid, _audit.Events[^1].Data["kid"]);
        Assert.True(_audit.Events[^1].Data.ContainsKey("remove_after"));
    }

    [Fact]
    public async Task Keys_stay_valid_over_a_long_simulation()
    {
        // Run the job every hour for 400 days, over four rotations.
        await ActiveKey();
        var rotations = 0;
        for (var hour = 0; hour < 400 * 24; hour++)
        {
            _time.Advance(TimeSpan.FromHours(1));
            if (await Maintain() == KeyMaintenanceAction.Rotated)
            {
                rotations++;
            }

            var now = _time.GetUtcNow();
            var active = Assert.Single(_keys.Keys, k => k.Status == SigningKeyStatus.Active);
            Assert.True(_keys.Keys.Count(k => k.Status == SigningKeyStatus.Pending) <= 1);

            // The signing key is always published, and has signed for at most one interval plus one job period.
            Assert.True(active.IsPublished(now));
            Assert.True(now - active.SigningFrom <= Options.RotationInterval + TimeSpan.FromHours(1));
        }

        Assert.Equal(4, rotations);
        Assert.Equal(4, _keys.Keys.Count(k => k.Status == SigningKeyStatus.Retired));
    }

    [Fact]
    public async Task Removing_the_active_key_takes_it_out_at_once_and_starts_a_replacement()
    {
        var key = await ActiveKey();
        var auditBefore = _audit.Events.Count;

        var result = await _service.RemoveCompromisedKeyAsync(_tenantId, key.Kid, "corr-r", CancellationToken.None);

        Assert.True(result.Found);
        Assert.True(result.WasActive);
        Assert.Equal(KeyMaintenanceAction.Created, result.Replacement);
        Assert.False(key.IsPublished(_time.GetUtcNow()));
        Assert.False(key.CanSign);
        Assert.Equal(
            [AuditEventTypes.KeyRemoved, AuditEventTypes.KeyCreated],
            _audit.Events.Skip(auditBefore).Select(e => e.Type));
        Assert.Single(_keys.Keys, k => k.Status == SigningKeyStatus.Pending);
    }

    [Fact]
    public async Task Removing_the_active_key_activates_a_ready_next_key_at_once()
    {
        var key = await ActiveKey();
        _time.Advance(Options.RotationInterval - Wait);
        await Maintain();
        _time.Advance(Wait);

        var result = await _service.RemoveCompromisedKeyAsync(_tenantId, key.Kid, "corr-r", CancellationToken.None);

        Assert.Equal(KeyMaintenanceAction.Activated, result.Replacement);
        Assert.Single(_keys.Keys, k => k.Status == SigningKeyStatus.Active);
    }

    [Fact]
    public async Task Removing_an_unknown_kid_changes_nothing()
    {
        await ActiveKey();
        var auditBefore = _audit.Events.Count;

        var result = await _service.RemoveCompromisedKeyAsync(_tenantId, "no-such-kid", "corr-r", CancellationToken.None);

        Assert.False(result.Found);
        Assert.Equal(auditBefore, _audit.Events.Count);
    }
}
