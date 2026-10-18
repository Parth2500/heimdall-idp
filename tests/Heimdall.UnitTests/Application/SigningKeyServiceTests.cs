using Heimdall.Application.Keys;
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
    public async Task The_oldest_ready_key_is_activated()
    {
        var older = await Create();
        _time.Advance(TimeSpan.FromMinutes(1));
        var newer = await Create();
        _time.Advance(Wait);

        var activated = await Activate();

        Assert.Same(older, activated);
        Assert.Equal(SigningKeyStatus.Pending, newer.Status);
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
        };

        Assert.Equal(3, options.Validate().Count);
        Assert.Empty(new SigningKeyOptions().Validate());
    }
}
