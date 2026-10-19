using Heimdall.Application.Alerts;
using Heimdall.Application.Audit;
using Heimdall.Application.Authorization;
using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Application.Sessions;
using Heimdall.Application.Tenants;
using Heimdall.Application.Tokens;
using Heimdall.Application.UserInfo;
using Heimdall.Application.Users;
using Heimdall.Infrastructure.Alerts;
using Heimdall.Infrastructure.Development;
using Heimdall.Infrastructure.Keys;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Purge;
using Heimdall.Infrastructure.Stores;
using Heimdall.Infrastructure.Telemetry;
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
    /// <param name="connectionString">The application role: a member of <c>heimdall_app</c>.</param>
    /// <param name="platformConnectionString">
    /// The platform role, a member of <c>heimdall_platform</c>, for jobs across tenants. Null uses
    /// <paramref name="connectionString"/>, which works only when that role bypasses row-level security (a superuser).
    /// </param>
    public static IServiceCollection AddHeimdallInfrastructure(
        this IServiceCollection services,
        string connectionString,
        string? platformConnectionString = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        return services.AddHeimdallInfrastructure(_ => connectionString, _ => platformConnectionString ?? connectionString);
    }

    /// <summary>Same as the other overload. The connection strings are read when the first database context is created.</summary>
    public static IServiceCollection AddHeimdallInfrastructure(
        this IServiceCollection services,
        Func<IServiceProvider, string> connectionString,
        Func<IServiceProvider, string>? platformConnectionString = null)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        platformConnectionString ??= connectionString;

        services.TryAddSingleton(new SigningKeyOptions());
        services.AddMetrics();
        services.TryAddSingleton<HeimdallMetrics>();
        services.AddScoped<TenantScope>();
        services.AddDbContext<HeimdallDbContext>((provider, options) =>
            ConfigureDbContext(options, connectionString(provider), provider.GetRequiredService<TenantScope>()));
        services.AddSingleton(provider => new PlatformDbContextFactory(platformConnectionString(provider)));
        services.AddSingleton<ITenantDirectory, TenantDirectory>();
        services.AddSingleton<ClientCache>();
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IUserStore, EfUserStore>();
        services.AddScoped<ILoginThrottleStore, EfLoginThrottleStore>();
        services.AddScoped<ISessionStore, EfSessionStore>();
        services.AddScoped<IAuthorizationStore, EfAuthorizationStore>();
        services.AddScoped<ITokenStore, EfTokenStore>();
        services.AddSingleton<ISecurityAlerts, LoggingSecurityAlerts>();
        services.TryAddSingleton(new PasswordHashingOptions());
        services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
        services.AddScoped<IAuditLog, EfAuditLog>();
        services.AddScoped<ISigningKeyStore, EfSigningKeyStore>();
        services.AddSingleton<ISigningKeyCache, SigningKeyCache>();
        services.AddSingleton<ITokenSigner, JwtTokenSigner>();
        services.AddSingleton<IAccessTokenValidator, AccessTokenValidator>();
        services.TryAddSingleton(new PurgeOptions());
        services.AddScoped<DataPurger>();
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

    /// <param name="scope">The tenant of the context. When set, each connection open sets <c>app.tenant_id</c> (D20).</param>
    internal static void ConfigureDbContext(DbContextOptionsBuilder options, string connectionString, TenantScope? scope = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        options.UseNpgsql(connectionString).UseSnakeCaseNamingConvention();
        if (scope is not null)
        {
            options.AddInterceptors(new TenantConnectionInterceptor(scope));
        }
    }
}
