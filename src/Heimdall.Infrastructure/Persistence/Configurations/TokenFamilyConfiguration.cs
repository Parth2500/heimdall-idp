using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class TokenFamilyConfiguration : IEntityTypeConfiguration<TokenFamily>
{
    public void Configure(EntityTypeBuilder<TokenFamily> builder)
    {
        builder.ToTable("token_families", t =>
        {
            t.HasCheckConstraint(
                "ck_token_families_revoked_reason",
                "revoked_reason IS NULL OR revoked_reason IN ('reuse_detected', 'user_logout', 'admin', 'user_disabled', 'consent_removed')");
            t.HasCheckConstraint("ck_token_families_idle", "idle_expires_at <= absolute_expires_at");
        });

        builder.HasKey(f => f.Id);
        builder.Property(f => f.Id).ValueGeneratedNever();

        // The target of the composite foreign key from refresh_tokens: a token and its family share a tenant.
        builder.HasAlternateKey(f => new { f.TenantId, f.Id });

        builder.HasOne<Tenant>().WithMany().HasForeignKey(f => f.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Client>().WithMany().HasForeignKey(f => f.ClientPk).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<User>().WithMany().HasForeignKey(f => f.UserId).OnDelete(DeleteBehavior.Restrict);

        // An audit reference only, with no foreign key (docs/schema-design.md, "Purge job").
        builder.Property(f => f.SourceCodeId);
        builder.Property(f => f.Scope).HasMaxLength(1024).IsRequired();
        builder.Property(f => f.CreatedAt);
        builder.Property(f => f.AbsoluteExpiresAt);
        builder.Property(f => f.IdleExpiresAt);
        builder.Property(f => f.RevokedAt);
        builder.Property(f => f.RevocationReason)
            .HasColumnName("revoked_reason")
            .HasConversion(new SnakeCaseEnumConverter<FamilyRevocationReason>())
            .HasMaxLength(32);

        // Revoke all families of a user or a client.
        builder.HasIndex(f => f.UserId);
        builder.HasIndex(f => f.ClientPk);
    }
}
