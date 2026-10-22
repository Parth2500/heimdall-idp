using Heimdall.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class DpopProofConfiguration : IEntityTypeConfiguration<DpopProofRecord>
{
    public void Configure(EntityTypeBuilder<DpopProofRecord> builder)
    {
        builder.ToTable("dpop_proofs", t => t.HasCheckConstraint("ck_dpop_proofs_hash_length", "octet_length(proof_hash) = 32"));

        // The replay check is an insert that conflicts on this key (D26).
        builder.HasKey(r => new { r.TenantId, r.ProofHash });
        builder.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.Property(r => r.ExpiresAt);

        // The purge job deletes rows whose window has ended.
        builder.HasIndex(r => r.ExpiresAt);
    }
}
