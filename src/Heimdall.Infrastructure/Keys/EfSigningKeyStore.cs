using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

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

    public void Add(SigningKey key) => _db.SigningKeys.Add(key);

    public Task SaveChangesAsync(CancellationToken cancellationToken) => _db.SaveChangesAsync(cancellationToken);
}
