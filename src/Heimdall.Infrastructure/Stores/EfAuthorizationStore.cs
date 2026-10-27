using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Heimdall.Domain.Common;
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

    public async Task<AuthorizationRequest?> TakePushedRequestAsync(
        Guid tenantId,
        TokenHash requestUriHash,
        Guid clientPk,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var hash = requestUriHash.ToArray();
        var until = now + AuthorizationRequest.Lifetime;

        // docs/schema-design.md, "Take a pushed request". One statement: a concurrent /authorize with the same
        // request_uri waits on the row lock, then finds the hash cleared and matches no row.
        var rows = await _db.AuthorizationRequests
            .FromSql($"""
                UPDATE authorization_requests
                SET    request_uri_hash = NULL, expires_at = {until}
                WHERE  tenant_id = {tenantId} AND request_uri_hash = {hash}
                  AND  client_pk = {clientPk} AND expires_at > {now}
                RETURNING *
                """)
            .IgnoreQueryFilters() // The tenant condition is in the statement. A filter would wrap it in a SELECT.
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return rows.SingleOrDefault();
    }

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
