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

internal sealed class InMemorySigningKeyStore : ISigningKeyStore
{
    public List<SigningKey> Keys { get; } = [];

    public int SaveCount { get; private set; }

    /// <summary>When true, the next save fails as if another server saved a conflicting change first.</summary>
    public bool LoseNextSave { get; set; }

    public Task<IReadOnlyList<SigningKey>> ListAsync(Guid tenantId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<SigningKey>>(Keys.Where(k => k.TenantId == tenantId).ToList());

    public Task<IReadOnlyList<Guid>> ListTenantsAwaitingActivationAsync(DateTimeOffset now, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public void Add(SigningKey key) => Keys.Add(key);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        if (LoseNextSave)
        {
            LoseNextSave = false;
            throw new ConcurrentUpdateException();
        }

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
