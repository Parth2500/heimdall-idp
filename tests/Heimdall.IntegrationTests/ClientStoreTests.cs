using Heimdall.Application.Clients;
using Heimdall.Domain.Common;
using Heimdall.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;

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
        await using var services = _postgres.CreateServices();
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
}
