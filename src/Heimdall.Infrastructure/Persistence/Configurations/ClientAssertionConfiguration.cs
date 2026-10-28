using Heimdall.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class ClientAssertionConfiguration : IEntityTypeConfiguration<ClientAssertionRecord>
{
    public void Configure(EntityTypeBuilder<ClientAssertionRecord> builder)
    {
        builder.ToTable("client_assertions", t => t.HasCheckConstraint("ck_client_assertions_hash_length", "octet_length(assertion_hash) = 32"));

        // The replay check is an insert that conflicts on this key (D49).
        builder.HasKey(r => new { r.TenantId, r.AssertionHash });
        builder.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.Property(r => r.ExpiresAt);

        // The purge job deletes rows whose assertion has expired.
        builder.HasIndex(r => r.ExpiresAt);
    }
}
