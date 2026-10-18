using Heimdall.Application.Common;
using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Heimdall.Infrastructure.Keys;

internal sealed class EfSigningKeyStore : ISigningKeyStore
{
    private readonly HeimdallDbContext _db;
    private readonly PlatformDbContextFactory _platform;

    public EfSigningKeyStore(HeimdallDbContext db, PlatformDbContextFactory platform)
    {
        _db = db;
        _platform = platform;
    }

    public async Task<IReadOnlyList<SigningKey>> ListAsync(Guid tenantId, CancellationToken cancellationToken) =>
        // The explicit tenant condition and the global query filter (D20) must both match.
        await _db.SigningKeys
            .Where(k => k.TenantId == tenantId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    public async Task<IReadOnlyList<Guid>> ListTenantsNeedingKeyWorkAsync(
        DateTimeOffset now,
        DateTimeOffset activeSigningSince,
        CancellationToken cancellationToken)
    {
        // A platform query across tenants, so it skips the tenant filter on purpose and uses the platform role, which
        // row-level security lets read every tenant. It returns tenant IDs only.
        var db = _platform.Create();
        await using var dispose = db.ConfigureAwait(false);
        var keys = db.SigningKeys.IgnoreQueryFilters();
        return await db.Tenants
            .Where(t =>
                // No key signs or waits to sign: create one.
                !keys.Any(k => k.TenantId == t.Id && (k.Status == SigningKeyStatus.Active || k.Status == SigningKeyStatus.Pending))

                // No active key, and a pending key is ready: activate it.
                || (!keys.Any(k => k.TenantId == t.Id && k.Status == SigningKeyStatus.Active)
                    && keys.Any(k => k.TenantId == t.Id && k.Status == SigningKeyStatus.Pending && k.SigningFrom <= now))

                // The active key is near or past its rotation time: create the next key, or rotate.
                || keys.Any(k => k.TenantId == t.Id && k.Status == SigningKeyStatus.Active && k.SigningFrom <= activeSigningSince))
            .Select(t => t.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public void Add(SigningKey key) => _db.SigningKeys.Add(key);

    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException exception) when (
            exception is DbUpdateConcurrencyException
            || exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            // Concurrency: another server changed the status of this key first.
            // Unique violation: another server activated a different key, or created the pending key, first.
            // Forget the refused changes, so a later save in this scope does not send them again.
            _db.ChangeTracker.Clear();
            throw new ConcurrentUpdateException("A concurrent change won. This change was not saved.", exception);
        }
    }
}
