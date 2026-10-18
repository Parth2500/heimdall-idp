using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Keys;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Persistence;

public sealed class HeimdallDbContext : DbContext
{
    private readonly TenantScope _scope;

    public HeimdallDbContext(DbContextOptions<HeimdallDbContext> options, TenantScope scope)
        : base(options)
    {
        _scope = scope;
    }

    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<User> Users => Set<User>();

    public DbSet<Client> Clients => Set<Client>();

    public DbSet<ClientSecretRecord> ClientSecrets => Set<ClientSecretRecord>();

    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();

    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    // EF Core reads this property for each query, so the filter uses the tenant of this context instance.
    private Guid? CurrentTenantId => _scope.TenantId;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(HeimdallDbContext).Assembly);

        // D20: every tenant-owned table is filtered by the current tenant. With no tenant, no rows match.
        // The tenants table has no filter: the host lookup runs before the tenant is known.
        modelBuilder.Entity<User>().HasQueryFilter(u => u.TenantId == CurrentTenantId);
        modelBuilder.Entity<Client>().HasQueryFilter(c => c.TenantId == CurrentTenantId);
        modelBuilder.Entity<ClientSecretRecord>().HasQueryFilter(s => s.TenantId == CurrentTenantId);
        modelBuilder.Entity<SigningKey>().HasQueryFilter(k => k.TenantId == CurrentTenantId);
    }
}
