using Heimdall.Application.Dpop;
using Heimdall.Domain.Common;
using Heimdall.Infrastructure.Dpop;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfDpopReplayStore : IDpopReplayStore
{
    // iat is rounded down to the second, so the real iat can be up to one second later.
    private static readonly TimeSpan Retention = DpopProofValidator.MaxClockDifference + TimeSpan.FromSeconds(1);

    private readonly HeimdallDbContext _db;

    public EfDpopReplayStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<bool> TryUseAsync(Guid tenantId, DpopProof proof, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proof);

        // The thumbprint has a fixed length of 43 characters, so "thumbprint:jti" has one reading.
        var hash = TokenHash.Compute(proof.KeyThumbprint + ":" + proof.Jti).ToArray();
        var expiresAt = proof.IssuedAt + Retention;

        // One statement (D26): the unique key decides. A concurrent insert of the same proof waits on the key, then
        // inserts nothing. No read happens first, so no check-then-act gap exists.
        var inserted = await _db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO dpop_proofs (tenant_id, proof_hash, expires_at)
            VALUES ({tenantId}, {hash}, {expiresAt})
            ON CONFLICT (tenant_id, proof_hash) DO NOTHING
            """,
            cancellationToken).ConfigureAwait(false);
        return inserted == 1;
    }
}
