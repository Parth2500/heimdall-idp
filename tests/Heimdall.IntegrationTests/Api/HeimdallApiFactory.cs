using System.Net.Http.Headers;
using System.Text;
using Heimdall.Api.Hosting;
using Heimdall.Api.Jobs;
using Heimdall.Application.Keys;
using Heimdall.Application.Tenants;
using Heimdall.Application.Users;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
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

            // The smallest allowed Argon2id parameters keep the tests fast.
            ["Heimdall:PasswordHashing:MemoryKiB"] = "19456",
        }));
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Time);

            // The fake clock jumps days in some tests. The purge loop must not run in the background then.
            foreach (var job in services.Where(d => d.ServiceType == typeof(IHostedService) && d.ImplementationType == typeof(PurgeJob)).ToList())
            {
                services.Remove(job);
            }
            services.RemoveAll<IKeyMaterialStore>();
            services.AddDevelopmentKeyFile(_postgres.KeyFilePath);
            services.Configure<IssuerOptions>(options => options.Port = null);
        });
    }

    public HttpClient ClientFor(string host, string scheme = "https", bool handleCookies = true) =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri($"{scheme}://{host}/"),
            AllowAutoRedirect = false,
            HandleCookies = handleCookies,
        });

    /// <summary>
    /// Adds a public browser client (a SPA): authorization code with PKCE and refresh tokens, no secret.
    /// </summary>
    public async Task<Client> AddWebClientAsync(
        TestTenant tenant,
        string clientId = "web-app",
        bool requireConsent = false,
        string[]? audiences = null,
        params string[] redirectUris)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            tenant.Tenant.Id,
            clientId,
            "Web app",
            ClientType.Public,
            [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "profile", "email", "offline_access"],
            redirectUris.Length > 0 ? redirectUris : ["https://app.example.com/callback"],
            requireConsent,
            overrides: null,
            Time.GetUtcNow(),
            audiences ?? ["https://api.example.com"]);
        client.Approve();

        await using var scope = Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Clients.Add(client);
        await db.SaveChangesAsync();
        return client;
    }

    /// <summary>Adds a user to the tenant with the real hasher.</summary>
    public async Task<User> AddUserAsync(TestTenant tenant, string email, string password)
    {
        await using var scope = Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync(password, CancellationToken.None);
        var user = User.Create(Guid.CreateVersion7(), tenant.Tenant.Id, email, hash, Time.GetUtcNow());
        var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
        users.Add(user);
        await users.SaveChangesAsync(CancellationToken.None);
        return user;
    }

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
