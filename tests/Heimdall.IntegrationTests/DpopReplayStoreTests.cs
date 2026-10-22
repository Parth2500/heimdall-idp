using Heimdall.Application.Dpop;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Purge;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.IntegrationTests;

/// <summary>
/// The DPoP replay store (D26) against PostgreSQL as the application role, so row-level security applies to each
/// insert and read.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class DpopReplayStoreTests
{
    private const string KeyA = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private const string KeyB = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    private readonly PostgresFixture _postgres;

    public DpopReplayStoreTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private async Task<(Guid A, Guid B)> AddTenantsAsync()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var a = TestData.NewTenant();
        var b = TestData.NewTenant();
        db.Tenants.AddRange(a, b);
        await db.SaveChangesAsync();
        return (a.Id, b.Id);
    }

    private static DpopProof Proof(string jti, string key = KeyA, DateTimeOffset? issuedAt = null) =>
        new(key, jti, issuedAt ?? DateTimeOffset.UtcNow);

    private static async Task<bool> UseAsync(ServiceProvider services, Guid tenantId, DpopProof proof)
    {
        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        return await scope.ServiceProvider.GetRequiredService<IDpopReplayStore>().TryUseAsync(tenantId, proof, CancellationToken.None);
    }

    [DockerFact]
    public async Task New_proof_is_accepted_and_its_replay_is_refused()
    {
        var (tenant, _) = await AddTenantsAsync();
        await using var services = _postgres.CreateServices();

        Assert.True(await UseAsync(services, tenant, Proof("jti-1")));
        Assert.False(await UseAsync(services, tenant, Proof("jti-1")));
        Assert.True(await UseAsync(services, tenant, Proof("jti-2")));
    }

    [DockerFact]
    public async Task Same_jti_from_another_key_is_another_proof()
    {
        // Otherwise one client could burn another client's jti in advance.
        var (tenant, _) = await AddTenantsAsync();
        await using var services = _postgres.CreateServices();

        Assert.True(await UseAsync(services, tenant, Proof("shared", KeyA)));
        Assert.True(await UseAsync(services, tenant, Proof("shared", KeyB)));
    }

    [DockerFact]
    public async Task Same_proof_in_another_tenant_is_another_proof()
    {
        var (a, b) = await AddTenantsAsync();
        await using var services = _postgres.CreateServices();

        Assert.True(await UseAsync(services, a, Proof("jti-1")));
        Assert.True(await UseAsync(services, b, Proof("jti-1")));
    }

    [DockerFact]
    public async Task Concurrent_uses_of_one_proof_give_exactly_one_success()
    {
        var (tenant, _) = await AddTenantsAsync();
        await using var services = _postgres.CreateServices();
        var proof = Proof("raced");

        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(() => UseAsync(services, tenant, proof))));

        Assert.Single(results, r => r);
    }

    [DockerFact]
    public async Task Row_is_written_only_into_the_request_tenant()
    {
        // Row-level security: a context of tenant A cannot record a proof for tenant B.
        var (a, b) = await AddTenantsAsync();
        await using var services = _postgres.CreateServices();

        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(a);
        var store = scope.ServiceProvider.GetRequiredService<IDpopReplayStore>();

        await Assert.ThrowsAsync<Npgsql.PostgresException>(() => store.TryUseAsync(b, Proof("cross"), CancellationToken.None));
    }

    [DockerFact]
    public async Task Row_lives_until_the_iat_window_ends_and_the_purge_then_deletes_it()
    {
        var (tenant, _) = await AddTenantsAsync();
        var issuedAt = new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
        await using var services = _postgres.CreateServices();
        await UseAsync(services, tenant, Proof("old", issuedAt: issuedAt));
        await UseAsync(services, tenant, Proof("live", issuedAt: DateTimeOffset.UtcNow));

        await using (var scope = services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant);
            var expiries = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().DpopProofs
                .Select(p => p.ExpiresAt).ToListAsync();
            Assert.Contains(issuedAt.AddSeconds(61), expiries);
        }

        // The purge runs with the platform role. Only the row whose window has ended goes.
        await using var purgeServices = _postgres.CreateServices(new FakeTimeProvider(issuedAt.AddSeconds(62)));
        await using var purgeScope = purgeServices.CreateAsyncScope();
        var result = await purgeScope.ServiceProvider.GetRequiredService<DataPurger>().RunOnceAsync(CancellationToken.None);

        Assert.True(result.DpopProofs >= 1);
        Assert.True(await UseAsync(services, tenant, Proof("old", issuedAt: issuedAt)));
        Assert.False(await UseAsync(services, tenant, Proof("live")));
    }
}
