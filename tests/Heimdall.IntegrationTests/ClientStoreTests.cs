using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Domain.Common;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.IntegrationTests;

[Collection(PostgresGroup.Name)]
public sealed class ClientStoreTests
{
    private readonly PostgresFixture _postgres;

    public ClientStoreTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private async Task<(Guid TenantId, Guid OtherTenantId)> SeedAsync()
    {
        // Setup data for two tenants, as the owner. The reads below use the application role.
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();

        var tenant = TestData.NewTenant();
        var other = TestData.NewTenant();
        var client = TestData.NewServiceClient(tenant.Id);

        db.Tenants.AddRange(tenant, other);
        db.Clients.Add(client);
        db.ClientSecrets.AddRange(
            TestData.Secret(client, "valid-secret"),
            TestData.Secret(client, "expired-secret", expiresAt: TestData.Now.AddDays(-1)),
            TestData.Secret(client, "revoked-secret", revokedAt: TestData.Now.AddDays(-2)));
        await db.SaveChangesAsync();

        return (tenant.Id, other.Id);
    }

    private async Task<ClientWithSecrets?> FindAsync(Guid? scopeTenant, Guid queryTenant, string clientId)
    {
        await using var services = _postgres.CreateServices();
        await using var scope = services.CreateAsyncScope();
        if (scopeTenant is { } id)
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(id);
        }

        return await scope.ServiceProvider.GetRequiredService<IClientStore>()
            .FindForAuthenticationAsync(queryTenant, clientId, TestData.Now, CancellationToken.None);
    }

    [DockerFact]
    public async Task Returns_the_client_with_only_its_valid_secrets()
    {
        var (tenantId, _) = await SeedAsync();

        var found = await FindAsync(tenantId, tenantId, "billing-service");

        Assert.NotNull(found);
        Assert.Equal("billing-service", found.Client.ClientId);
        var hash = Assert.Single(found.ValidSecretHashes);
        Assert.Equal(TokenHash.Compute("valid-secret"), hash);
        Assert.Equal(["https://api.example.com"], found.Client.AllowedAudiences);
    }

    [DockerFact]
    public async Task Unknown_client_returns_null()
    {
        var (tenantId, _) = await SeedAsync();

        Assert.Null(await FindAsync(tenantId, tenantId, "no-such-client"));
    }

    [DockerFact]
    public async Task Query_filter_hides_a_client_of_another_tenant()
    {
        var (tenantId, otherTenantId) = await SeedAsync();

        // The scope is tenant B, the query asks for tenant A. The filter must win.
        Assert.Null(await FindAsync(otherTenantId, tenantId, "billing-service"));
    }

    [DockerFact]
    public async Task Without_a_tenant_scope_no_client_is_returned()
    {
        var (tenantId, _) = await SeedAsync();

        Assert.Null(await FindAsync(null, tenantId, "billing-service"));
    }

    /// <summary>One server: one service provider, so one cache, with a fake clock.</summary>
    private static async Task<ClientWithSecrets?> FindOnServerAsync(ServiceProvider server, Guid tenantId, DateTimeOffset now)
    {
        await using var scope = server.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        return await scope.ServiceProvider.GetRequiredService<IClientStore>()
            .FindForAuthenticationAsync(tenantId, "billing-service", now, CancellationToken.None);
    }

    private async Task RevokeAllSecretsAsync(Guid tenantId)
    {
        await using var admin = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        await using var scope = admin.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().ClientSecrets
            .IgnoreQueryFilters()
            .Where(s => s.TenantId == tenantId)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, TestData.Now));
    }

    [DockerFact]
    public async Task A_change_on_another_server_shows_after_the_cache_lifetime()
    {
        var (tenantId, _) = await SeedAsync();
        var time = new FakeTimeProvider(TestData.Now);
        await using var server = _postgres.CreateServices(time);
        Assert.Single((await FindOnServerAsync(server, tenantId, TestData.Now))!.ValidSecretHashes);

        // Another server revokes the secret. This server still has the old entry.
        await RevokeAllSecretsAsync(tenantId);
        Assert.Single((await FindOnServerAsync(server, tenantId, TestData.Now))!.ValidSecretHashes);

        time.Advance(server.GetRequiredService<SigningKeyOptions>().ServerCacheLifetime);
        Assert.Empty((await FindOnServerAsync(server, tenantId, TestData.Now))!.ValidSecretHashes);
    }

    [DockerFact]
    public async Task Invalidate_shows_a_change_at_once()
    {
        var (tenantId, _) = await SeedAsync();
        await using var server = _postgres.CreateServices(new FakeTimeProvider(TestData.Now));
        Assert.Single((await FindOnServerAsync(server, tenantId, TestData.Now))!.ValidSecretHashes);

        await RevokeAllSecretsAsync(tenantId);
        server.GetRequiredService<ClientCache>().Invalidate(tenantId);

        Assert.Empty((await FindOnServerAsync(server, tenantId, TestData.Now))!.ValidSecretHashes);
    }

    [DockerFact]
    public async Task Secret_expiry_is_checked_at_each_read_not_at_load()
    {
        var (tenantId, _) = await SeedAsync();
        await using (var admin = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString))
        await using (var scope = admin.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var client = await db.Clients.IgnoreQueryFilters().SingleAsync(c => c.TenantId == tenantId);
            db.ClientSecrets.Add(TestData.Secret(client, "rotating-secret", expiresAt: TestData.Now.AddSeconds(10)));
            await db.SaveChangesAsync();
        }

        await using var server = _postgres.CreateServices(new FakeTimeProvider(TestData.Now));

        Assert.Equal(2, (await FindOnServerAsync(server, tenantId, TestData.Now))!.ValidSecretHashes.Count);
        Assert.Single((await FindOnServerAsync(server, tenantId, TestData.Now.AddSeconds(10)))!.ValidSecretHashes);
    }
}
