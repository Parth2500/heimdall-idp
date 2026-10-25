using Heimdall.Application.Users;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Purge;

/// <summary>The rows that one purge pass deleted, for each table.</summary>
public sealed record PurgeResult(int Families, int Codes, int Requests, int Sessions, int LoginThrottles, int DpopProofs, int BackchannelLogouts = 0);

/// <summary>
/// Deletes rows that no flow needs any more (docs/schema-design.md, "Purge job"). It is a platform operation across all
/// tenants, so it uses SQL statements, not the tenant query filter, and the platform role
/// (<see cref="PlatformDbContextFactory"/>).
/// </summary>
/// <remarks>
/// Each statement deletes at most <see cref="PurgeOptions.BatchSize"/> rows, and the pass repeats it until fewer rows
/// remain. <c>FOR UPDATE SKIP LOCKED</c> lets the job run on every server at once: a row that another transaction
/// holds is left for the next pass. The time comes from <see cref="TimeProvider"/>, not from <c>now()</c>.
/// </remarks>
public sealed class DataPurger
{
    private readonly PlatformDbContextFactory _platform;
    private readonly PurgeOptions _options;
    private readonly LoginThrottleOptions _throttle;
    private readonly TimeProvider _time;

    public DataPurger(PlatformDbContextFactory platform, PurgeOptions options, LoginThrottleOptions throttle, TimeProvider time)
    {
        _platform = platform;
        _options = options;
        _throttle = throttle;
        _time = time;
    }

    public async Task<PurgeResult> RunOnceAsync(CancellationToken cancellationToken)
    {
        // The platform role: row-level security lets it delete in every tenant.
        var db = _platform.Create();
        await using var dispose = db.ConfigureAwait(false);
        var now = _time.GetUtcNow();
        var batch = _options.BatchSize;

        // Families first. ON DELETE CASCADE removes their refresh tokens. ON DELETE SET NULL frees their codes, which
        // the next statement can then delete. idle_expires_at is never after absolute_expires_at (check constraint),
        // so it is the end of an unrevoked family.
        var familyCutoff = now - _options.FamilyRetention;
        var families = await RepeatAsync(
            () => db.Database.ExecuteSqlAsync(
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
            () => db.Database.ExecuteSqlAsync(
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
            () => db.Database.ExecuteSqlAsync(
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
            () => db.Database.ExecuteSqlAsync(
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

        // A source with no failure for the reset time starts from zero anyway. A running wait is kept until it ends.
        var throttleCutoff = now - _throttle.ResetAfter;
        var throttles = await RepeatAsync(
            () => db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM login_throttles
                WHERE (tenant_id, user_id, source_key) IN (
                    SELECT tenant_id, user_id, source_key FROM login_throttles
                    WHERE  last_failure_at < {throttleCutoff} AND (throttled_until IS NULL OR throttled_until < {now})
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        // A DPoP proof row matters only while its iat window lasts (D26). After that it needs no retention.
        var proofs = await RepeatAsync(
            () => db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM dpop_proofs
                WHERE (tenant_id, proof_hash) IN (
                    SELECT tenant_id, proof_hash FROM dpop_proofs
                    WHERE  expires_at < {now}
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        // D35: an undelivered logout older than the retention is of no use. A client session that old has ended too.
        var logoutCutoff = now - _options.BackchannelLogoutRetention;
        var logouts = await RepeatAsync(
            () => db.Database.ExecuteSqlAsync(
                $"""
                DELETE FROM backchannel_logouts
                WHERE id IN (
                    SELECT id FROM backchannel_logouts
                    WHERE  created_at < {logoutCutoff}
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                """,
                cancellationToken),
            cancellationToken).ConfigureAwait(false);

        return new PurgeResult(families, codes, requests, sessions, throttles, proofs, logouts);
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
