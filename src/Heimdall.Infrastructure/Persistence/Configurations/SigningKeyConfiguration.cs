using Heimdall.Domain.Keys;
using Heimdall.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class SigningKeyConfiguration : IEntityTypeConfiguration<SigningKey>
{
    public void Configure(EntityTypeBuilder<SigningKey> builder)
    {
        builder.ToTable("signing_keys", t =>
        {
            t.HasCheckConstraint("ck_signing_keys_status", "status IN ('pending', 'active', 'retired')");
            t.HasCheckConstraint("ck_signing_keys_algorithm", $"algorithm = '{SigningKey.Algorithm}'");
            t.HasCheckConstraint("ck_signing_keys_private_ref", "private_key_ref NOT ILIKE '%PRIVATE KEY%'");
        });

        builder.HasKey(k => k.Id);
        builder.Property(k => k.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(k => k.TenantId).OnDelete(DeleteBehavior.Restrict);

        builder.Property(k => k.Kid).HasMaxLength(64).IsRequired();
        builder.HasIndex(k => new { k.TenantId, k.Kid }).IsUnique();
        builder.Property(k => k.PublicJwk).HasColumnType("jsonb").IsRequired();
        builder.Property(k => k.PrivateKeyRef).HasMaxLength(512).IsRequired();
        builder.Property(k => k.Status).HasConversion(new SnakeCaseEnumConverter<SigningKeyStatus>()).HasMaxLength(32);
        builder.Property(k => k.PublishedAt);
        builder.Property(k => k.SigningFrom);
        builder.Property(k => k.RetiredAt);
        builder.Property(k => k.RemoveAfter);

        // The algorithm is a constant in the Domain. The column and its check make the rule visible in the database.
        // NOT NULL matters: a CHECK on a NULL value passes in SQL.
        builder.Property<string>("Algorithm").HasMaxLength(16).IsRequired().HasDefaultValue(SigningKey.Algorithm);

        // A tenant has at most one active key.
        builder.HasIndex([nameof(SigningKey.TenantId)], "ux_signing_keys_one_active")
            .IsUnique()
            .HasFilter("status = 'active'")
            .HasDatabaseName("ux_signing_keys_one_active");

        builder.Ignore(k => k.CanSign);
    }
}
