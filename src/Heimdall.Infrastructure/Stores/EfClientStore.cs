using Heimdall.Application.Clients;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfClientStore : IClientStore
{
    private readonly HeimdallDbContext _db;

    public EfClientStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<ClientWithSecrets?> FindForAuthenticationAsync(
        Guid tenantId,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // One SQL statement: the client and its valid secret hashes. The explicit tenant condition and the
        // global query filter (D20) must both match.
        var row = await _db.Clients
            .AsNoTracking()
            .Where(c => c.TenantId == tenantId && c.ClientId == clientId)
            .Select(c => new
            {
                Client = c,
                Secrets = _db.ClientSecrets
                    .Where(s => s.TenantId == c.TenantId && s.ClientPk == c.Id)
                    .Where(s => s.RevokedAt == null && (s.ExpiresAt == null || s.ExpiresAt > now))
                    .Select(s => s.SecretHash)
                    .ToList(),
            })
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return row is null ? null : new ClientWithSecrets(row.Client, row.Secrets);
    }
}
