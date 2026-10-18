using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(t => t.Id);
        builder.Property(t => t.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(t => t.TenantId).OnDelete(DeleteBehavior.Restrict);

        // Composite foreign key: a token can only belong to a family of its own tenant (D20).
        builder.HasOne<TokenFamily>()
            .WithMany()
            .HasForeignKey(t => new { t.TenantId, t.FamilyId })
            .HasPrincipalKey(f => new { f.TenantId, f.Id })
            .OnDelete(DeleteBehavior.Cascade);
        builder.HasIndex(t => t.FamilyId);

        // D3: only the hash. Unique, so the rotation lookup can never match two rows.
        builder.Property(t => t.Hash).HasColumnName("token_hash").HasConversion(Converters.Hash).HasMaxLength(32);
        builder.HasIndex(t => new { t.TenantId, t.Hash }).IsUnique();

        builder.Property(t => t.CreatedAt);
        builder.Property(t => t.UsedAt);
        builder.HasOne<RefreshToken>().WithMany().HasForeignKey(t => t.ReplacedById).OnDelete(DeleteBehavior.Restrict);
    }
}
