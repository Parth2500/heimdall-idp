using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests;

/// <summary>
/// Value objects are mapped as EF Core complex properties. Two entities can share one instance,
/// as tenants share <see cref="TenantSettings.Default"/>, and each row still gets its own values.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class ValueMappingTests
{
    private readonly PostgresFixture _postgres;

    public ValueMappingTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task Two_tenants_that_share_the_default_settings_are_saved_in_one_call()
    {
        var first = TestData.NewTenant();
        var second = TestData.NewTenant();
        Assert.Same(first.Settings, second.Settings);

        await using (var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString))
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            db.Tenants.AddRange(first, second);
            await db.SaveChangesAsync();
        }

        await using (var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString))
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var loaded = await db.Tenants.Where(t => t.Id == first.Id || t.Id == second.Id).ToListAsync();

            Assert.Equal(2, loaded.Count);
            Assert.All(loaded, t => Assert.Equal(TenantSettings.Default, t.Settings));
        }
    }

    [DockerFact]
    public async Task Clients_that_share_one_overrides_instance_keep_their_values()
    {
        var tenant = TestData.NewTenant();
        var shared = new ClientTokenOverrides(TimeSpan.FromMinutes(2), null, null);
        var first = TestData.NewServiceClient(tenant.Id, "first");
        var second = TestData.NewServiceClient(tenant.Id, "second");
        var plain = TestData.NewServiceClient(tenant.Id, "plain");
        first.UpdateTokenOverrides(shared);
        second.UpdateTokenOverrides(shared);

        await using (var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString))
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            db.Tenants.Add(tenant);
            db.Clients.AddRange(first, second, plain);
            await db.SaveChangesAsync();
        }

        await using (var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString))
        await using (var scope = services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var loaded = await db.Clients.ToDictionaryAsync(c => c.ClientId);

            Assert.Equal(shared, loaded["first"].TokenOverrides);
            Assert.Equal(shared, loaded["second"].TokenOverrides);
            Assert.Equal(ClientTokenOverrides.None, loaded["plain"].TokenOverrides);
        }
    }
}
