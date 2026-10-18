using System.Net;
using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Development;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.IntegrationTests;

[Collection(PostgresGroup.Name)]
public sealed class AuditAndSeedTests
{
    private readonly PostgresFixture _postgres;

    public AuditAndSeedTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task Audit_event_round_trips_with_its_data_and_ip()
    {
        var id = Guid.CreateVersion7();
        await using (var services = _postgres.CreateServices())
        await using (var scope = services.CreateAsyncScope())
        {
            var audit = scope.ServiceProvider.GetRequiredService<IAuditLog>();
            await audit.WriteAsync(
                AuditEvent.Record(
                    id,
                    Guid.CreateVersion7(),
                    AuditEventTypes.TokenRejected,
                    "corr-42",
                    TestData.Now,
                    IPAddress.Parse("203.0.113.7"),
                    data: new Dictionary<string, string> { ["error"] = "invalid_client", ["reason"] = "wrong secret" }),
                CancellationToken.None);
        }

        await using (var services = _postgres.CreateServices())
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var stored = await db.AuditEvents.AsNoTracking().SingleAsync(e => e.Id == id);

            Assert.Equal(AuditEventTypes.TokenRejected, stored.Type);
            Assert.Equal(IPAddress.Parse("203.0.113.7"), stored.SourceIp);
            Assert.Equal("wrong secret", stored.Data["reason"]);
            Assert.Equal(TestData.Now, stored.OccurredAt);
        }
    }

    [DockerFact]
    public async Task Seeded_client_authenticates_with_the_secret_that_was_shown_once()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var keyOptions = new SigningKeyOptions();

        SeedResult first;
        await using (var services = _postgres.CreateServices(time, keyOptions))
        await using (var scope = services.CreateAsyncScope())
        {
            first = await scope.ServiceProvider.GetRequiredService<DevelopmentSeeder>().SeedAsync(CancellationToken.None);
        }

        // The first key waits one JWKS cache lifetime. A later run activates it.
        time.Advance(keyOptions.JwksCacheLifetime);

        SeedResult second;
        await using (var services = _postgres.CreateServices(time, keyOptions))
        await using (var scope = services.CreateAsyncScope())
        {
            second = await scope.ServiceProvider.GetRequiredService<DevelopmentSeeder>().SeedAsync(CancellationToken.None);
        }

        Assert.True(first.Created);
        Assert.NotNull(first.ClientSecret);
        Assert.Equal(SigningKeyStatus.Pending, first.KeyStatus);
        Assert.False(second.Created);
        Assert.Null(second.ClientSecret);
        Assert.Equal(first.Kid, second.Kid);
        Assert.Equal(SigningKeyStatus.Active, second.KeyStatus);

        await using (var services = _postgres.CreateServices())
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var tenant = await db.Tenants.SingleAsync(t => t.Host == DevelopmentSeeder.TenantHost);
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);

            var authenticator = new ClientAuthenticator(
                scope.ServiceProvider.GetRequiredService<IClientStore>(),
                TimeProvider.System);

            var good = await authenticator.AuthenticateAsync(tenant.Id, DevelopmentSeeder.ClientId, first.ClientSecret, CancellationToken.None);
            var bad = await authenticator.AuthenticateAsync(tenant.Id, DevelopmentSeeder.ClientId, "wrong", CancellationToken.None);

            Assert.True(good.IsSuccess);
            Assert.False(bad.IsSuccess);
        }
    }
}
