using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users", t =>
        {
            t.HasCheckConstraint("ck_users_status", "status IN ('active', 'disabled')");

            // Only an encoded Argon2id hash fits here, never a plain password or another algorithm (D3).
            t.HasCheckConstraint("ck_users_password_hash", "password_hash LIKE '$argon2id$%'");
        });

        builder.HasKey(u => u.Id);
        builder.Property(u => u.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(u => u.TenantId).OnDelete(DeleteBehavior.Restrict);

        // RFC 5321 limits an address to 254 characters in practice. 320 leaves room for the raw form.
        builder.Property(u => u.Email).HasMaxLength(320).IsRequired();
        builder.Property(u => u.EmailNormalized).HasMaxLength(320).IsRequired();
        builder.HasIndex(u => new { u.TenantId, u.EmailNormalized }).IsUnique();

        builder.Property(u => u.PasswordHash).HasMaxLength(256).IsRequired();
        builder.Property(u => u.Status).HasConversion(new SnakeCaseEnumConverter<UserStatus>()).HasMaxLength(32);
        builder.Property(u => u.CreatedAt);
        builder.Property(u => u.PasswordChangedAt);
    }
}
