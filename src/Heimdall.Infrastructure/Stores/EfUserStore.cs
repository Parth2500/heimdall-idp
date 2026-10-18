using Heimdall.Application.Common;
using Heimdall.Application.Users;
using Heimdall.Domain.Users;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfUserStore : IUserStore
{
    private readonly HeimdallDbContext _db;

    public EfUserStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public Task<User?> FindByEmailAsync(Guid tenantId, string emailNormalized, CancellationToken cancellationToken) =>
        // The explicit tenant condition and the global query filter (D20) must both match.
        _db.Users.SingleOrDefaultAsync(u => u.TenantId == tenantId && u.EmailNormalized == emailNormalized, cancellationToken);

    public Task<User?> FindByIdAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        _db.Users.SingleOrDefaultAsync(u => u.TenantId == tenantId && u.Id == userId, cancellationToken);

    public void Add(User user) => _db.Users.Add(user);

    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException exception) when (exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            _db.ChangeTracker.Clear();
            throw new ConcurrentUpdateException("A user with this email already exists in the tenant.", exception);
        }
    }
}
