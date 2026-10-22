using Heimdall.Application.Audit;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests;

/// <summary>The group-commit audit writer, against PostgreSQL as the application role.</summary>
[Collection(PostgresGroup.Name)]
public sealed class BatchingAuditLogTests
{
    private readonly PostgresFixture _postgres;

    public BatchingAuditLogTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static AuditEvent Event(Guid tenantId, string correlationId = "corr-batch") =>
        AuditEvent.Record(Guid.CreateVersion7(), tenantId, AuditEventTypes.UserInfoRead, correlationId, TestData.Now);

    /// <summary>Reads the tenant's audit rows through a new context, as another request would.</summary>
    /// <remarks>audit_events has no row-level security and no query filter, so the tenant condition is explicit.</remarks>
    private static async Task<HashSet<Guid>> ReadIdsAsync(ServiceProvider services, Guid tenantId)
    {
        await using var scope = services.CreateAsyncScope();
        var ids = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents
            .AsNoTracking()
            .Where(e => e.TenantId == tenantId)
            .Select(e => e.Id)
            .ToListAsync();
        return [.. ids];
    }

    [DockerFact]
    public async Task Written_event_is_committed_before_the_call_returns()
    {
        await using var services = _postgres.CreateServices();
        var audit = services.GetRequiredService<IAuditLog>();
        var tenantId = Guid.CreateVersion7();
        var auditEvent = Event(tenantId);

        await audit.WriteAsync(auditEvent, CancellationToken.None);

        Assert.Contains(auditEvent.Id, await ReadIdsAsync(services, tenantId));
    }

    [DockerFact]
    public async Task Concurrent_events_share_transactions_and_keep_their_tenants()
    {
        await using var services = _postgres.CreateServices();
        var writer = services.GetRequiredService<BatchingAuditLog>();
        var tenants = Enumerable.Range(0, 3).Select(_ => Guid.CreateVersion7()).ToArray();
        var events = Enumerable.Range(0, 300).Select(i => Event(tenants[i % 3])).ToList();

        await Task.WhenAll(events.Select(e => writer.WriteAsync(e, CancellationToken.None)));

        // 300 events in far fewer commits: the events that waited during one commit went into the next one.
        Assert.InRange(writer.Commits, 1, 299);
        foreach (var tenant in tenants)
        {
            var expected = events.Where(e => e.TenantId == tenant).Select(e => e.Id).ToHashSet();
            Assert.Equal(expected, await ReadIdsAsync(services, tenant));
        }
    }

    [DockerFact]
    public async Task Bad_event_fails_only_its_own_caller()
    {
        await using var services = _postgres.CreateServices();
        var audit = services.GetRequiredService<IAuditLog>();
        var tenantId = Guid.CreateVersion7();
        var good = Enumerable.Range(0, 20).Select(_ => Event(tenantId)).ToList();

        // correlation_id holds at most 128 characters, so the database refuses this event.
        var bad = Event(tenantId, new string('c', 200));
        var writes = good.Take(10).Append(bad).Concat(good.Skip(10)).Select(e => (Event: e, Task: audit.WriteAsync(e, CancellationToken.None))).ToList();

        await Assert.ThrowsAsync<DbUpdateException>(() => writes.Single(w => w.Event == bad).Task);
        await Task.WhenAll(writes.Where(w => w.Event != bad).Select(w => w.Task));
        Assert.Equal(good.Select(e => e.Id).ToHashSet(), await ReadIdsAsync(services, tenantId));
    }

    [DockerFact]
    public async Task Caller_that_stops_waiting_still_gets_its_event_written()
    {
        await using var services = _postgres.CreateServices();
        var audit = services.GetRequiredService<IAuditLog>();
        var tenantId = Guid.CreateVersion7();
        var first = Event(tenantId);
        var second = Event(tenantId);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => audit.WriteAsync(first, new CancellationToken(canceled: true)));

        // The queue keeps its order, so once the second event is committed, the first one is too.
        await audit.WriteAsync(second, CancellationToken.None);
        Assert.Equal(new HashSet<Guid> { first.Id, second.Id }, await ReadIdsAsync(services, tenantId));
    }

    [DockerFact]
    public async Task Writes_after_disposal_are_refused()
    {
        var services = _postgres.CreateServices();
        var writer = services.GetRequiredService<BatchingAuditLog>();
        await services.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => writer.WriteAsync(Event(Guid.CreateVersion7()), CancellationToken.None));
    }
}
