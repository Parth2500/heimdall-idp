using Heimdall.Application.Sessions;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;
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

    public async Task<(Session Session, User User)?> FindWithUserAsync(Guid tenantId, TokenHash idHash, CancellationToken cancellationToken)
    {
        // Both tables carry the tenant filter and row-level security. The join also requires the same tenant.
        var found = await (
                from s in _db.Sessions
                where s.TenantId == tenantId && s.IdHash == idHash
                join u in _db.Users on new { s.TenantId, Id = s.UserId } equals new { u.TenantId, u.Id }
                select new { Session = s, User = u })
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        return found is null ? null : (found.Session, found.User);
    }

    public void Add(Session session) => _db.Sessions.Add(session);

    public Task SaveChangesAsync(CancellationToken cancellationToken) => _db.SaveChangesAsync(cancellationToken);
}
