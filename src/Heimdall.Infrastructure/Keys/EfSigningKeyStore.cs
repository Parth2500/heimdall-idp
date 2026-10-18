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

    public EfSigningKeyStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<IReadOnlyList<SigningKey>> ListAsync(Guid tenantId, CancellationToken cancellationToken) =>
        // The explicit tenant condition and the global query filter (D20) must both match.
        await _db.SigningKeys
            .Where(k => k.TenantId == tenantId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    public async Task<IReadOnlyList<Guid>> ListTenantsAwaitingActivationAsync(DateTimeOffset now, CancellationToken cancellationToken) =>
        // A platform query across tenants, so it skips the tenant filter on purpose. It returns tenant IDs only.
        await _db.SigningKeys
            .IgnoreQueryFilters()
            .Where(k => k.Status == SigningKeyStatus.Pending && k.SigningFrom <= now)
            .Where(k => !_db.SigningKeys.IgnoreQueryFilters().Any(a => a.TenantId == k.TenantId && a.Status == SigningKeyStatus.Active))
            .Select(k => k.TenantId)
            .Distinct()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

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
            // Unique violation: another server activated a different key of this tenant first.
            // Forget the refused changes, so a later save in this scope does not send them again.
            _db.ChangeTracker.Clear();
            throw new ConcurrentUpdateException("A concurrent change won. This change was not saved.", exception);
        }
    }
}
