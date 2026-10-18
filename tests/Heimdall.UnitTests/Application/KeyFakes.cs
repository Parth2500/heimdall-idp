using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Application.Keys;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;

namespace Heimdall.UnitTests.Application;

internal sealed class FakeKeyMaterialStore : IKeyMaterialStore
{
    private int _count;

    public Task<CreatedKeyMaterial> CreateRsaKeyAsync(CancellationToken cancellationToken)
    {
        // Distinct public parameters give each key a distinct thumbprint (kid).
        var number = Interlocked.Increment(ref _count);
        return Task.FromResult(new CreatedKeyMaterial($"fake:{number}", $"modulus{number}", "AQAB"));
    }

    public Task<byte[]> SignRs256Async(string privateKeyRef, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

/// <summary>Enforces the same rules as the database: one active and one pending key for each tenant.</summary>
internal sealed class InMemorySigningKeyStore : ISigningKeyStore
{
    private readonly List<SigningKey> _unsaved = [];

    public List<SigningKey> Keys { get; } = [];

    public int SaveCount { get; private set; }

    /// <summary>When true, the next save fails as if another server saved a conflicting change first.</summary>
    public bool LoseNextSave { get; set; }

    public Task<IReadOnlyList<SigningKey>> ListAsync(Guid tenantId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SigningKey>>(Keys.Where(k => k.TenantId == tenantId).ToList());

    public Task<IReadOnlyList<Guid>> ListTenantsNeedingKeyWorkAsync(
        DateTimeOffset now,
        DateTimeOffset activeSigningSince,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public void Add(SigningKey key)
    {
        Keys.Add(key);
        _unsaved.Add(key);
    }

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var broken = Keys
            .GroupBy(k => (k.TenantId, k.Status))
            .Any(g => g.Key.Status != SigningKeyStatus.Retired && g.Count() > 1);
        if (LoseNextSave || broken)
        {
            LoseNextSave = false;
            Keys.RemoveAll(_unsaved.Contains);
            _unsaved.Clear();
            throw new ConcurrentUpdateException();
        }

        _unsaved.Clear();
        SaveCount++;
        return Task.CompletedTask;
    }
}

internal sealed class RecordingSigningKeyCache : ISigningKeyCache
{
    public List<Guid> Invalidated { get; } = [];

    public ValueTask<ActiveSigningKey?> GetActiveKeyAsync(Guid tenantId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public ValueTask<IReadOnlyList<RsaPublicJwk>> GetPublishedKeysAsync(Guid tenantId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public void Invalidate(Guid tenantId) => Invalidated.Add(tenantId);
}

internal sealed class RecordingAuditLog : IAuditLog
{
    public List<AuditEvent> Events { get; } = [];

    public Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        Events.Add(auditEvent);
        return Task.CompletedTask;
    }
}
