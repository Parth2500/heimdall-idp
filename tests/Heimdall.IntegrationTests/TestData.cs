using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure.Persistence;

namespace Heimdall.IntegrationTests;

internal static class TestData
{
    public static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Each test gets its own tenant, so tests can share one database without conflicts.</summary>
    public static Tenant NewTenant() =>
        Tenant.Create(Guid.CreateVersion7(), $"t{Guid.NewGuid():N}.test", "Test tenant", TenantSettings.Default, Now);

    public static Client NewServiceClient(Guid tenantId, string clientId = "billing-service")
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            tenantId,
            clientId,
            "Billing service",
            ClientType.Confidential,
            [GrantType.ClientCredentials],
            ["invoices.read"],
            [],
            requireConsent: false,
            overrides: null,
            Now,
            ["https://api.example.com"]);
        client.Approve();
        return client;
    }

    public static ClientSecretRecord Secret(
        Client client,
        string value,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? revokedAt = null) => new()
        {
            Id = Guid.CreateVersion7(),
            TenantId = client.TenantId,
            ClientPk = client.Id,
            SecretHash = TokenHash.Compute(value),
            CreatedAt = Now,
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt,
        };
}
