using Heimdall.Application;
using Heimdall.Application.Keys;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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

    public string ConnectionString =>
        _container?.GetConnectionString() ?? throw new InvalidOperationException("Docker is not available.");

    public async Task InitializeAsync()
    {
        if (!DockerAvailability.IsAvailable)
        {
            return;
        }

        _container = new PostgreSqlBuilder("postgres:17").Build();
        await _container.StartAsync();

        await using var provider = CreateServices();
        await using var scope = provider.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().Database.MigrateAsync();
    }

    public ServiceProvider CreateServices(TimeProvider? time = null, SigningKeyOptions? keyOptions = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(time ?? TimeProvider.System);
        services.AddSingleton(keyOptions ?? new SigningKeyOptions());
        services.AddHeimdallApplication();
        services.AddHeimdallInfrastructure(ConnectionString);
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
