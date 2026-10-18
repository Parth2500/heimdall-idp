using Heimdall.Api.Jobs;
using Heimdall.Application.Common;
using Heimdall.Application.Keys;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.IntegrationTests.Api;

/// <summary>The key activation job, and the database rule that makes it safe on many servers.</summary>
[Collection(PostgresGroup.Name)]
public sealed class ActivationJobTests
{
    private readonly PostgresFixture _postgres;

    public ActivationJobTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    /// <summary>Creates a tenant with one pending key. Returns the tenant ID.</summary>
    private static async Task<Guid> AddTenantWithPendingKeyAsync(HeimdallApiFactory api)
    {
        var tenant = TestData.NewTenant();
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();

        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
        await scope.ServiceProvider.GetRequiredService<SigningKeyService>().CreateKeyAsync(tenant.Id, "test", CancellationToken.None);
        return tenant.Id;
    }

    private static async Task<List<SigningKey>> KeysOfAsync(HeimdallApiFactory api, Guid tenantId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().SigningKeys.AsNoTracking().ToListAsync();
    }

    [DockerFact]
    public async Task Job_activates_a_pending_key_only_after_its_wait()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenantId = await AddTenantWithPendingKeyAsync(api);
        var job = api.Services.GetRequiredService<SigningKeyActivationJob>();

        api.Time.Advance(api.KeyOptions.PublishWait - TimeSpan.FromSeconds(1));
        await job.RunOnceAsync(CancellationToken.None);
        Assert.Equal(SigningKeyStatus.Pending, Assert.Single(await KeysOfAsync(api, tenantId)).Status);

        api.Time.Advance(TimeSpan.FromSeconds(1));
        await job.RunOnceAsync(CancellationToken.None);
        Assert.Equal(SigningKeyStatus.Active, Assert.Single(await KeysOfAsync(api, tenantId)).Status);
    }

    [DockerFact]
    public async Task Two_servers_running_the_job_activate_exactly_one_key()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var serverA = new HeimdallApiFactory(_postgres, time);
        await using var serverB = new HeimdallApiFactory(_postgres, time);
        var tenantId = await AddTenantWithPendingKeyAsync(serverA);

        // A second pending key, so each server could pick a different one.
        await using (var scope = serverB.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
            await scope.ServiceProvider.GetRequiredService<SigningKeyService>().CreateKeyAsync(tenantId, "test", CancellationToken.None);
        }

        time.Advance(serverA.KeyOptions.PublishWait + TimeSpan.FromSeconds(1));
        var jobA = serverA.Services.GetRequiredService<SigningKeyActivationJob>();
        var jobB = serverB.Services.GetRequiredService<SigningKeyActivationJob>();

        await Task.WhenAll(Enumerable.Range(0, 4).Select(i => (i % 2 == 0 ? jobA : jobB).RunOnceAsync(CancellationToken.None)));

        // Whatever the interleaving, the tenant ends with one active key and one activation event.
        // (The run count is not checked: the jobs also activate keys that other tests left in the shared database.)
        var keys = await KeysOfAsync(serverA, tenantId);
        Assert.Single(keys, k => k.Status == SigningKeyStatus.Active);

        await using var auditScope = serverA.Services.CreateAsyncScope();
        var db = auditScope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        Assert.Equal(1, await db.AuditEvents.CountAsync(e => e.TenantId == tenantId && e.Type == AuditEventTypes.KeyActivated));
    }

    [DockerFact]
    public async Task Store_reports_a_lost_activation_as_a_concurrent_update()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenantId = await AddTenantWithPendingKeyAsync(api);
        api.Time.Advance(api.KeyOptions.PublishWait);

        await using var scopeA = api.Services.CreateAsyncScope();
        await using var scopeB = api.Services.CreateAsyncScope();
        scopeA.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        scopeB.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        var storeA = scopeA.ServiceProvider.GetRequiredService<ISigningKeyStore>();
        var storeB = scopeB.ServiceProvider.GetRequiredService<ISigningKeyStore>();

        // Both servers read the same pending key before either saves. Then each adds and activates a key.
        var keyB = SigningKey.Create(Guid.CreateVersion7(), tenantId, "second", "{}", "devfile:x", TimeSpan.FromSeconds(1), api.Time.GetUtcNow());
        storeB.Add(keyB);
        await storeB.SaveChangesAsync(CancellationToken.None);
        api.Time.Advance(TimeSpan.FromSeconds(1));

        var fromA = (await storeA.ListAsync(tenantId, CancellationToken.None)).Single(k => k.Kid != "second");
        var fromB = (await storeB.ListAsync(tenantId, CancellationToken.None)).Single(k => k.Kid == "second");
        SigningKeyRotation.ActivateFirst(fromA, api.Time.GetUtcNow());
        SigningKeyRotation.ActivateFirst(fromB, api.Time.GetUtcNow());

        await storeA.SaveChangesAsync(CancellationToken.None);
        await Assert.ThrowsAsync<ConcurrentUpdateException>(() => storeB.SaveChangesAsync(CancellationToken.None));
        Assert.Single(await KeysOfAsync(api, tenantId), k => k.Status == SigningKeyStatus.Active);
    }

    [DockerFact]
    public async Task Awaiting_list_skips_tenants_with_an_active_key_or_an_unfinished_wait()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        // AddTenantAsync advances the clock by one publish wait, so it runs first.
        var active = (await api.AddTenantAsync()).Tenant.Id;
        var ready = await AddTenantWithPendingKeyAsync(api);
        api.Time.Advance(api.KeyOptions.PublishWait);
        var waiting = await AddTenantWithPendingKeyAsync(api);

        await using var scope = api.Services.CreateAsyncScope();
        var awaiting = await scope.ServiceProvider.GetRequiredService<ISigningKeyStore>()
            .ListTenantsAwaitingActivationAsync(api.Time.GetUtcNow(), CancellationToken.None);

        Assert.Contains(ready, awaiting);
        Assert.DoesNotContain(waiting, awaiting);
        Assert.DoesNotContain(active, awaiting);
    }
}
