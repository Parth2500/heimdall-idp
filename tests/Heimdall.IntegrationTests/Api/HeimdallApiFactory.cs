using System.Net.Http.Headers;
using System.Text;
using Heimdall.Api.Hosting;
using Heimdall.Application.Clients;
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
using Microsoft.EntityFrameworkCore;
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
    private readonly string _environment;

    static HeimdallApiFactory()
    {
        // Each host watches its configuration files for changes, and each watcher uses one inotify instance. Linux
        // allows 128 for each user by default, shared with the IDE. Hundreds of test hosts would run out, so the test
        // hosts read configuration once. The variable must be set before the first host is built.
        Environment.SetEnvironmentVariable("DOTNET_hostBuilder__reloadConfigOnChange", "false");
    }

    public HeimdallApiFactory(PostgresFixture postgres, FakeTimeProvider? time = null, string environment = "Development")
    {
        _postgres = postgres;
        _environment = environment;
        Time = time ?? new FakeTimeProvider(DateTimeOffset.UtcNow);
    }

    public FakeTimeProvider Time { get; }

    public SigningKeyOptions KeyOptions => Services.GetRequiredService<SigningKeyOptions>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(_environment);
        builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Heimdall"] = _postgres.ConnectionString,
            ["ConnectionStrings:HeimdallPlatform"] = _postgres.PlatformConnectionString,

            // The tests run job passes themselves, so the background loops must not race them. A loop's first pass
            // could otherwise create a key for a tenant that a test is still setting up.
            ["Heimdall:Jobs:Enabled"] = "false",

            // Every test request comes from one address. RateLimitTests sets low limits on purpose.
            ["Heimdall:RateLimits:Login:PermitLimit"] = "1000",
            ["Heimdall:RateLimits:Authorize:PermitLimit"] = "1000",
            ["Heimdall:RateLimits:ClientFailures:PermitLimit"] = "1000",
            ["Heimdall:RateLimits:ClientIssuance:PermitLimit"] = "1000",

            // The smallest allowed Argon2id parameters keep the tests fast.
            ["Heimdall:PasswordHashing:MemoryKiB"] = "19456",

            // A small stand-in for the Angular build, so the tests do not need Node.js.
            ["Heimdall:Ui:AccountDirectory"] = AccountFixture.Directory,
        }));
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Time);
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
        bool requireDpop = false,
        string[]? postLogoutRedirectUris = null,
        string? backchannelLogoutUri = null,
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
            audiences ?? ["https://api.example.com"],
            requireDpop);
        client.UpdateLogoutUris(postLogoutRedirectUris ?? [], backchannelLogoutUri);
        client.Approve();

        await using var scope = Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Clients.Add(client);
        await db.SaveChangesAsync();
        return client;
    }

    /// <summary>Disables a client and drops the tenant's clients from this server's cache, as an admin change does.</summary>
    public async Task DisableClientAsync(TestTenant tenant, Guid clientPk)
    {
        await using var scope = Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var client = await db.Clients.SingleAsync(c => c.Id == clientPk);
        client.Disable();
        await db.SaveChangesAsync();
        scope.ServiceProvider.GetRequiredService<IClientStore>().Invalidate(tenant.Tenant.Id);
    }

    /// <summary>Sets the audiences that the tenant's confidential client serves (D37), as an admin change does.</summary>
    public async Task SetResourceAudiencesAsync(TestTenant tenant, params string[] audiences)
    {
        await using var scope = Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var client = await db.Clients.SingleAsync(c => c.ClientId == tenant.ClientId);
        client.UpdateResourceAudiences(audiences);
        await db.SaveChangesAsync();
        scope.ServiceProvider.GetRequiredService<IClientStore>().Invalidate(tenant.Tenant.Id);
    }

    /// <summary>Switches the tenant's confidential client to private_key_jwt with these public keys (D45, D46).</summary>
    public async Task UsePrivateKeyJwtAsync(TestTenant tenant, string jwks)
    {
        await using var scope = Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var client = await db.Clients.SingleAsync(c => c.ClientId == tenant.ClientId);
        client.UsePrivateKeyJwt(jwks);
        await db.SaveChangesAsync();
        scope.ServiceProvider.GetRequiredService<IClientStore>().Invalidate(tenant.Tenant.Id);
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

/// <summary>A stand-in for the built account application: an index with the nonce placeholder and one hashed bundle.</summary>
internal static class AccountFixture
{
    public const string Bundle = "main-ABCD1234.js";
    public const string Font = "media/ibm-plex-sans-latin-wght-ABCD1234.woff2";

    private static readonly Lazy<string> Root = new(() =>
    {
        var directory = Path.Combine(Path.GetTempPath(), "heimdall-account-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);
        File.WriteAllText(
            Path.Combine(directory, "index.html"),
            $"<!doctype html><html><head><script src=\"{Bundle}\" nonce=\"__HEIMDALL_CSP_NONCE__\"></script></head>" +
            "<body><acct-root ngCspNonce=\"__HEIMDALL_CSP_NONCE__\"></acct-root></body></html>");
        File.WriteAllText(Path.Combine(directory, Bundle), "console.log('account');");
        System.IO.Directory.CreateDirectory(Path.Combine(directory, "media"));
        File.WriteAllBytes(Path.Combine(directory, Font), [0x77, 0x4F, 0x46, 0x32]);
        return directory;
    });

    public static string Directory => Root.Value;
}
