using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Infrastructure.Development;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddHeimdallInfrastructure(this IServiceCollection services, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddScoped<TenantScope>();
        services.AddDbContext<HeimdallDbContext>(options => ConfigureDbContext(options, connectionString));
        services.AddScoped<IClientStore, EfClientStore>();
        services.AddScoped<IAuditLog, EfAuditLog>();
        services.AddScoped<DevelopmentSeeder>();
        return services;
    }

    internal static void ConfigureDbContext(DbContextOptionsBuilder options, string connectionString) =>
        options.UseNpgsql(connectionString).UseSnakeCaseNamingConvention();
}
