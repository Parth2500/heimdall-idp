using Heimdall.Application.Logout;
using Heimdall.Domain.Common;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfLogoutStore : ILogoutStore
{
    private readonly HeimdallDbContext _db;

    public EfLogoutStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<SessionEnd> EndSessionAsync(
        Guid tenantId,
        TokenHash sessionIdHash,
        string sid,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var hash = sessionIdHash.ToArray();
        var transaction = await _db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using (transaction.ConfigureAwait(false))
        {
            // docs/schema-design.md, "End a session". The conditional update is the lock: a concurrent sign-out of the
            // same session waits on the row, then matches no row and changes nothing.
            var ended = await _db.Database.ExecuteSqlAsync(
                $"""
                UPDATE sessions SET revoked_at = {now}
                WHERE  tenant_id = {tenantId} AND id_hash = {hash} AND revoked_at IS NULL
                """,
                cancellationToken).ConfigureAwait(false);
            if (ended == 0)
            {
                return SessionEnd.None;
            }

            // D33: every family of this sign-in, also with offline_access. A family that a reuse revoked keeps its reason.
            var families = await _db.Database.SqlQuery<RevokedFamily>(
                $"""
                UPDATE token_families SET revoked_at = {now}, revoked_reason = 'user_logout'
                WHERE  tenant_id = {tenantId} AND sid = {sid} AND revoked_at IS NULL
                RETURNING id AS family_id, client_pk, user_id
                """)
                .ToListAsync(cancellationToken).ConfigureAwait(false);

            // D34: one delivery for each client that got tokens in this session, revoked families included, because the
            // client can still hold a session of its own. A redeemed code always has a family, so families are enough.
            var queued = await _db.Database.SqlQuery<Guid>(
                $"""
                INSERT INTO backchannel_logouts (id, tenant_id, client_pk, user_id, sid, created_at, attempts, next_attempt_at)
                SELECT gen_random_uuid(), f.tenant_id, f.client_pk, f.user_id, f.sid, {now}, 0, {now}
                FROM   (SELECT DISTINCT tenant_id, client_pk, user_id, sid
                        FROM   token_families
                        WHERE  tenant_id = {tenantId} AND sid = {sid}) AS f
                JOIN   clients AS c ON c.tenant_id = f.tenant_id AND c.id = f.client_pk
                WHERE  c.backchannel_logout_uri IS NOT NULL
                RETURNING client_pk AS value
                """)
                .ToListAsync(cancellationToken).ConfigureAwait(false);

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return new SessionEnd(true, families, queued);
        }
    }
}
