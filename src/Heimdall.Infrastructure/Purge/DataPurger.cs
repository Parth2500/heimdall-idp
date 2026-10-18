using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Purge;

/// <summary>The rows that one purge pass deleted, for each table.</summary>
public sealed record PurgeResult(int Families, int Codes, int Requests, int Sessions);

/// <summary>
/// Deletes rows that no flow needs any more (docs/schema-design.md, "Purge job"). It is a platform operation across all
/// tenants, so it uses SQL statements, not the tenant query filter.
/// </summary>
/// <remarks>
/// Each statement deletes at most <see cref="PurgeOptions.BatchSize"/> rows, and the pass repeats it until fewer rows
/// remain. <c>FOR UPDATE SKIP LOCKED</c> lets the job run on every server at once: a row that another transaction
/// holds is left for the next pass. The time comes from <see cref="TimeProvider"/>, not from <c>now()</c>.
/// </remarks>
public sealed class DataPurger
{
    private readonly HeimdallDbContext _db;
    private readonly PurgeOptions _options;
    private readonly TimeProvider _time;

    public DataPurger(HeimdallDbContext db, PurgeOptions options, TimeProvider time)
    {
        _db = db;
        _options = options;
        _time = time;
    }

    public async Task<PurgeResult> RunOnceAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var batch = _options.BatchSize;

        // Families first. ON DELETE CASCADE removes their refresh tokens. ON DELETE SET NULL frees their codes, which
        // the next statement can then delete. idle_expires_at is never after absolute_expires_at (check constraint),
        // so it is the end of an unrevoked family.
        var familyCutoff = now - _options.FamilyRetention;
        var families = await RepeatAsync(
            () => _db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM token_families
                WHERE id IN (
                    SELECT id FROM token_families
                    WHERE  idle_expires_at < {familyCutoff} OR revoked_at < {familyCutoff}
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        var codeCutoff = now - _options.CodeRetention;
        var codes = await RepeatAsync(
            () => _db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM authorization_codes
                WHERE id IN (
                    SELECT id FROM authorization_codes
                    WHERE  expires_at < {codeCutoff} AND family_id IS NULL
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        var requests = await RepeatAsync(
            () => _db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM authorization_requests
                WHERE id IN (
                    SELECT id FROM authorization_requests
                    WHERE  expires_at < {now}
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        // A session that ended by its idle timeout stays until its absolute limit plus the retention. The idle timeout
        // is a tenant setting, and this keeps the statement on one table with simple indexes.
        var sessionCutoff = now - _options.SessionRetention;
        var sessions = await RepeatAsync(
            () => _db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM sessions
                WHERE id_hash IN (
                    SELECT id_hash FROM sessions
                    WHERE  absolute_expires_at < {sessionCutoff} OR revoked_at < {sessionCutoff}
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        return new PurgeResult(families, codes, requests, sessions);
    }

    private async Task<int> RepeatAsync(Func<Task<int>> deleteBatch, CancellationToken cancellationToken)
    {
        var total = 0;
        int deleted;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            deleted = await deleteBatch().ConfigureAwait(false);
            total += deleted;
        }
        while (deleted == _options.BatchSize);

        return total;
    }
}
