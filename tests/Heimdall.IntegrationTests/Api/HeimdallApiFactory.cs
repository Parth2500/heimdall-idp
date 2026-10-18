using System.Net.Http.Headers;
using System.Text;
using Heimdall.Api.Hosting;
using Heimdall.Application.Keys;
using Heimdall.Application.Tenants;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// Hosts the real Api (Program.cs and its middleware) in memory, against the test PostgreSQL. Each instance acts as
/// one server, with its own caches. The clock is fake, so key waits pass without real waiting.
/// </summary>
internal sealed class HeimdallApiFactory : WebApplicationFactory<Program>
{
    private readonly PostgresFixture _postgres;

    public HeimdallApiFactory(PostgresFixture postgres, FakeTimeProvider? time = null)
    {
        _postgres = postgres;
        Time = time ?? new FakeTimeProvider(DateTimeOffset.UtcNow);
    }

    public FakeTimeProvider Time { get; }

    public SigningKeyOptions KeyOptions => Services.GetRequiredService<SigningKeyOptions>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Heimdall"] = _postgres.ConnectionString,

            // The tests call the activation job themselves, so the background loop must not race them.
            ["Heimdall:SigningKeys:ActivationCheckInterval"] = "1.00:00:00",
        }));
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Time);
            services.RemoveAll<IKeyMaterialStore>();
            services.AddDevelopmentKeyFile(_postgres.KeyFilePath);
            services.Configure<IssuerOptions>(options => options.Port = null);
        });
    }

    public HttpClient ClientFor(string host, string scheme = "https") =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri($"{scheme}://{host}/"),
            AllowAutoRedirect = false,
        });

    /// <summary>Creates a tenant with one confidential client and an active signing key.</summary>
    public async Task<TestTenant> AddTenantAsync(string clientSecret = "s3cret-value-for-tests")
    {
        var tenant = TestData.NewTenant();
        var client = TestData.NewServiceClient(tenant.Id);

        await using (var scope = Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
            db.Tenants.Add(tenant);
            db.Clients.Add(client);
            db.ClientSecrets.Add(TestData.Secret(client, clientSecret));
            await db.SaveChangesAsync();

            var keys = scope.ServiceProvider.GetRequiredService<SigningKeyService>();
            await keys.CreateKeyAsync(tenant.Id, "test", CancellationToken.None);
            Time.Advance(KeyOptions.PublishWait);
            Assert.NotNull(await keys.ActivateFirstKeyAsync(tenant.Id, "test", CancellationToken.None));
        }

        Services.GetRequiredService<ITenantDirectory>().Invalidate();
        return new TestTenant(tenant, client.ClientId, clientSecret);
    }

    public static AuthenticationHeaderValue Basic(string clientId, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(
            Uri.EscapeDataString(clientId) + ":" + Uri.EscapeDataString(secret))));
}

internal sealed record TestTenant(Tenant Tenant, string ClientId, string ClientSecret)
{
    public string Host => Tenant.Host;

    public string Issuer => "https://" + Tenant.Host;
}
