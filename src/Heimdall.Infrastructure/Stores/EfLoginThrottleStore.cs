using Heimdall.Application.Users;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

/// <summary>
/// <c>login_throttles</c>. Each write is one statement, so two servers that record failures at the same time both count.
/// Row-level security applies: every statement runs in the request's tenant.
/// </summary>
internal sealed class EfLoginThrottleStore : ILoginThrottleStore
{
    private readonly HeimdallDbContext _db;

    public EfLoginThrottleStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<DateTimeOffset?> GetThrottledUntilAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken) =>
        await _db.LoginThrottles.AsNoTracking()
            .Where(r => r.TenantId == tenantId && r.UserId == userId && r.SourceKey == sourceKey)
            .Select(r => r.ThrottledUntil)
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

    public async Task<int> RecordFailureAsync(
        Guid tenantId,
        Guid userId,
        string sourceKey,
        DateTimeOffset now,
        DateTimeOffset resetBefore,
        CancellationToken cancellationToken)
    {
        // Insert the first failure, or add one. A row whose last failure is old starts again at one, with no wait.
        var counts = await _db.Database.SqlQuery<int>(
            $"""
            INSERT INTO login_throttles (tenant_id, user_id, source_key, failures, last_failure_at, throttled_until)
            VALUES ({tenantId}, {userId}, {sourceKey}, 1, {now}, NULL)
            ON CONFLICT (tenant_id, user_id, source_key) DO UPDATE
            SET failures = CASE WHEN login_throttles.last_failure_at < {resetBefore} THEN 1 ELSE login_throttles.failures + 1 END,
                throttled_until = CASE WHEN login_throttles.last_failure_at < {resetBefore} THEN NULL ELSE login_throttles.throttled_until END,
                last_failure_at = {now}
            RETURNING failures AS "Value"
            """).ToListAsync(cancellationToken).ConfigureAwait(false);
        return counts.Single();
    }

    public Task ThrottleUntilAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset until, CancellationToken cancellationToken) =>
        _db.Database.ExecuteSqlAsync(
            $"""
            UPDATE login_throttles
            SET    throttled_until = GREATEST(COALESCE(throttled_until, {until}), {until})
            WHERE  tenant_id = {tenantId} AND user_id = {userId} AND source_key = {sourceKey}
            """,
            cancellationToken);

    public Task ResetAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken) =>
        _db.Database.ExecuteSqlAsync(
            $"DELETE FROM login_throttles WHERE tenant_id = {tenantId} AND user_id = {userId} AND source_key = {sourceKey}",
            cancellationToken);
}
