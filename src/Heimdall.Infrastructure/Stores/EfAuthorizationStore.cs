using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfAuthorizationStore : IAuthorizationStore
{
    private readonly HeimdallDbContext _db;

    public EfAuthorizationStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public void AddRequest(AuthorizationRequest request) => _db.AuthorizationRequests.Add(request);

    public Task<AuthorizationRequest?> FindRequestAsync(Guid tenantId, Guid requestId, CancellationToken cancellationToken) =>
        // The explicit tenant condition and the global query filter (D20) must both match.
        _db.AuthorizationRequests.SingleOrDefaultAsync(r => r.TenantId == tenantId && r.Id == requestId, cancellationToken);

    public void RemoveRequest(AuthorizationRequest request) => _db.AuthorizationRequests.Remove(request);

    public void AddCode(AuthorizationCode code) => _db.AuthorizationCodes.Add(code);

    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            // The DELETE of the request matched no row: another caller used the request first.
            // EF Core rolls back the whole SaveChanges, so the new code is not saved either.
            _db.ChangeTracker.Clear();
            throw new ConcurrentUpdateException("The authorization request was already used.", exception);
        }
    }
}
