using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class LoginThrottleConfiguration : IEntityTypeConfiguration<LoginThrottleRecord>
{
    public void Configure(EntityTypeBuilder<LoginThrottleRecord> builder)
    {
        builder.ToTable("login_throttles", t => t.HasCheckConstraint("ck_login_throttles_failures", "failures >= 1"));

        // One row for each account and source. The upsert relies on this key.
        builder.HasKey(r => new { r.TenantId, r.UserId, r.SourceKey });
        builder.Property(r => r.SourceKey).HasMaxLength(64);
        builder.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<User>().WithMany().HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.Cascade);
        builder.Property(r => r.Failures);
        builder.Property(r => r.LastFailureAt);
        builder.Property(r => r.ThrottledUntil);

        // The purge job deletes rows with no recent failure.
        builder.HasIndex(r => r.LastFailureAt);
    }
}
