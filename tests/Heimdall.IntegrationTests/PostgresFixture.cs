using Heimdall.Application;
using Heimdall.Application.Keys;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Heimdall.IntegrationTests;

/// <summary>
/// Starts one PostgreSQL container for all integration tests and applies the migrations once.
/// The tests use the real service registration (<see cref="Heimdall.Infrastructure.DependencyInjection.AddHeimdallInfrastructure"/>).
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _container;

    /// <summary>One development key file for the whole run, in a temporary folder.</summary>
    public string KeyFilePath { get; } =
        Path.Combine(Path.GetTempPath(), "heimdall-tests", Guid.NewGuid().ToString("N"), "signing-keys.json");

    /// <summary>
    /// The application role (a member of <c>heimdall_app</c>), as in production. Row-level security applies to it, so
    /// every test also runs against the second tenant layer (D20).
    /// </summary>
    public string ConnectionString => WithLogin(AppLogin);

    /// <summary>The platform role (a member of <c>heimdall_platform</c>), for jobs across tenants.</summary>
    public string PlatformConnectionString => WithLogin(PlatformLogin);

    /// <summary>The container superuser. It owns the tables and bypasses row-level security. Migrations and setup only.</summary>
    public string AdminConnectionString =>
        _container?.GetConnectionString() ?? throw new InvalidOperationException("Docker is not available.");

    private const string AppLogin = "heimdall_app_login";
    private const string PlatformLogin = "heimdall_platform_login";
    private const string TestPassword = "test-only-password";

    public async Task InitializeAsync()
    {
        if (!DockerAvailability.IsAvailable)
        {
            return;
        }

        _container = new PostgreSqlBuilder("postgres:17").Build();
        await _container.StartAsync();

        // The migrations run as the owner and create the group roles. The login roles are per environment, as in
        // production: an operator creates them and grants the group roles.
        await using var provider = CreateServices(connectionString: AdminConnectionString);
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        await db.Database.MigrateAsync();
        await db.Database.ExecuteSqlRawAsync($"""
            CREATE ROLE {AppLogin} LOGIN PASSWORD '{TestPassword}' IN ROLE heimdall_app;
            CREATE ROLE {PlatformLogin} LOGIN PASSWORD '{TestPassword}' IN ROLE heimdall_platform;
            """);
    }

    private string WithLogin(string login) =>
        new NpgsqlConnectionStringBuilder(AdminConnectionString) { Username = login, Password = TestPassword }.ConnectionString;

    public ServiceProvider CreateServices(TimeProvider? time = null, SigningKeyOptions? keyOptions = null, string? connectionString = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(time ?? TimeProvider.System);
        services.AddLogging();
        services.AddSingleton(keyOptions ?? new SigningKeyOptions());
        services.AddHeimdallApplication();
        services.AddHeimdallInfrastructure(connectionString ?? ConnectionString, PlatformConnectionString);
        services.AddDevelopmentKeyFile(KeyFilePath);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    public async Task DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }

        var directory = Path.GetDirectoryName(KeyFilePath)!;
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresGroup : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}
