using Heimdall.Application.Clients;
using Heimdall.Domain.Common;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfClientAssertionReplayStore : IClientAssertionReplayStore
{
    private readonly HeimdallDbContext _db;

    public EfClientAssertionReplayStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<bool> TryUseAsync(Guid tenantId, Guid clientPk, ClientAssertion assertion, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        // A GUID has a fixed format of 36 characters, so "client:jti" has one reading.
        var hash = TokenHash.Compute(clientPk.ToString("D") + ":" + assertion.Jti).ToArray();

        // The validator accepts an exp up to the clock difference in the past, so the row must live that much longer.
        var expiresAt = assertion.ExpiresAt + ClientAssertionTypes.MaxClockDifference;

        // One statement (D49): the unique key decides, as for DPoP proofs (D26). No read happens first.
        var inserted = await _db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO client_assertions (tenant_id, assertion_hash, expires_at)
            VALUES ({tenantId}, {hash}, {expiresAt})
            ON CONFLICT (tenant_id, assertion_hash) DO NOTHING
            """,
            cancellationToken).ConfigureAwait(false);
        return inserted == 1;
    }
}
