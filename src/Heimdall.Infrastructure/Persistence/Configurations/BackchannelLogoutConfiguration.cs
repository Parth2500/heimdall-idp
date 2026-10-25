using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class BackchannelLogoutConfiguration : IEntityTypeConfiguration<BackchannelLogoutRecord>
{
    public void Configure(EntityTypeBuilder<BackchannelLogoutRecord> builder)
    {
        builder.ToTable("backchannel_logouts", t =>
        {
            t.HasCheckConstraint("ck_backchannel_logouts_sid", "length(sid) = 22");
            t.HasCheckConstraint("ck_backchannel_logouts_attempts", "attempts >= 0");
        });

        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Restrict);

        // Composite foreign key: a delivery goes only to a client of its own tenant (D20).
        builder.HasOne<Client>()
            .WithMany()
            .HasForeignKey(r => new { r.TenantId, r.ClientPk })
            .HasPrincipalKey(c => new { c.TenantId, c.Id })
            .OnDelete(DeleteBehavior.Cascade);

        // No foreign key to the user: the row only names the sub of the logout token.
        builder.Property(r => r.UserId);
        builder.Property(r => r.Sid).HasMaxLength(22).IsFixedLength().IsRequired();
        builder.Property(r => r.CreatedAt);
        builder.Property(r => r.Attempts);
        builder.Property(r => r.NextAttemptAt);

        // The delivery job takes the due rows by this column. The purge job removes old rows by created_at.
        builder.HasIndex(r => r.NextAttemptAt);
        builder.HasIndex(r => r.CreatedAt);
    }
}
