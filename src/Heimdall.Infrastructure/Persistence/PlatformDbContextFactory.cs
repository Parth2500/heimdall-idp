using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Persistence;

/// <summary>
/// Creates database contexts for platform jobs that work across tenants: the key job's tenant list and the purge job.
/// They connect with the platform connection string, whose role is a member of <c>heimdall_platform</c>. Only that
/// role passes the row-level security policies for every tenant (docs/schema-design.md, "Row-level security").
/// </summary>
/// <remarks>The context has no tenant, so the EF Core tenant filter matches no row. Platform code uses SQL or <c>IgnoreQueryFilters</c>.</remarks>
public sealed class PlatformDbContextFactory
{
    private readonly string _connectionString;

    public PlatformDbContextFactory(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
    }

    public HeimdallDbContext Create()
    {
        var scope = new TenantScope();
        var options = new DbContextOptionsBuilder<HeimdallDbContext>();
        DependencyInjection.ConfigureDbContext(options, _connectionString, scope);
        return new HeimdallDbContext(options.Options, scope);
    }
}
