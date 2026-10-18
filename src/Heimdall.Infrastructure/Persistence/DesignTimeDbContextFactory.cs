using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Heimdall.Infrastructure.Persistence;

/// <summary>
/// Used only by <c>dotnet ef migrations add</c>. Creating a migration does not open a connection,
/// so the connection string here has no credentials.
/// </summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<HeimdallDbContext>
{
    public HeimdallDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<HeimdallDbContext>();
        DependencyInjection.ConfigureDbContext(options, "Host=localhost;Database=heimdall_design");
        return new HeimdallDbContext(options.Options, new TenantScope());
    }
}
