using Heimdall.Application.Sessions;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfSessionStore : ISessionStore
{
    private readonly HeimdallDbContext _db;

    public EfSessionStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public Task<Session?> FindAsync(Guid tenantId, TokenHash idHash, CancellationToken cancellationToken) =>
        // The explicit tenant condition and the global query filter (D20) must both match.
        _db.Sessions.SingleOrDefaultAsync(s => s.TenantId == tenantId && s.IdHash == idHash, cancellationToken);

    public void Add(Session session) => _db.Sessions.Add(session);

    public Task SaveChangesAsync(CancellationToken cancellationToken) => _db.SaveChangesAsync(cancellationToken);
}
