using Heimdall.Application.Audit;
using Heimdall.Application.Authorization;
using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Application.Sessions;
using Heimdall.Application.Tenants;
using Heimdall.Application.Users;
using Heimdall.Application.Tokens;
using Heimdall.Infrastructure.Development;
using Heimdall.Infrastructure.Keys;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Stores;
using Heimdall.Infrastructure.Tenants;
using Heimdall.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Heimdall.Infrastructure;

public static class DependencyInjection
{
    /// <summary>
    /// Registers the database, the stores, the caches, and the token signer. The caller must also register a key
    /// store (<see cref="IKeyMaterialStore"/>). Without one, the service provider fails to build.
    /// </summary>
    public static IServiceCollection AddHeimdallInfrastructure(this IServiceCollection services, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        return services.AddHeimdallInfrastructure(_ => connectionString);
    }

    /// <summary>Same as the other overload. The connection string is read when the first database context is created.</summary>
    public static IServiceCollection AddHeimdallInfrastructure(
        this IServiceCollection services,
        Func<IServiceProvider, string> connectionString)
    {
        ArgumentNullException.ThrowIfNull(connectionString);

        services.TryAddSingleton(new SigningKeyOptions());
        services.AddScoped<TenantScope>();
        services.AddDbContext<HeimdallDbContext>((provider, options) => ConfigureDbContext(options, connectionString(provider)));
        services.AddSingleton<ITenantDirectory, TenantDirectory>();
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IUserStore, EfUserStore>();
        services.AddScoped<ISessionStore, EfSessionStore>();
        services.AddScoped<IAuthorizationStore, EfAuthorizationStore>();
        services.TryAddSingleton(new PasswordHashingOptions());
        services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
        services.AddScoped<IAuditLog, EfAuditLog>();
        services.AddScoped<ISigningKeyStore, EfSigningKeyStore>();
        services.AddSingleton<ISigningKeyCache, SigningKeyCache>();
        services.AddSingleton<ITokenSigner, JwtTokenSigner>();
        services.AddScoped<DevelopmentSeeder>();
        return services;
    }

    /// <summary>
    /// Registers the development key file as the key store. Call it only in the Development environment
    /// (docs/schema-design.md, "Local development signing keys").
    /// </summary>
    public static IServiceCollection AddDevelopmentKeyFile(this IServiceCollection services, string path)
    {
        // A factory, so the container owns and disposes the instance.
        services.AddSingleton<IKeyMaterialStore>(_ => new DevelopmentKeyFile(path));
        return services;
    }

    internal static void ConfigureDbContext(DbContextOptionsBuilder options, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        options.UseNpgsql(connectionString).UseSnakeCaseNamingConvention();
    }
}
