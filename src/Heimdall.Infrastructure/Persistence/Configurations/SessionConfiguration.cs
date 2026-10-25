using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class SessionConfiguration : IEntityTypeConfiguration<Session>
{
    public void Configure(EntityTypeBuilder<Session> builder)
    {
        builder.ToTable("sessions", t => t.HasCheckConstraint("ck_sessions_sid", "length(sid) = 22"));

        // D12: the key is the SHA-256 hash of the session ID. The ID itself is never stored.
        builder.HasKey(s => s.IdHash);
        builder.Property(s => s.IdHash).HasConversion(Converters.Hash).HasMaxLength(32).ValueGeneratedNever();

        builder.HasOne<Tenant>().WithMany().HasForeignKey(s => s.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<User>().WithMany().HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Restrict);

        // Ending all sessions of a user (password change, disable) looks them up by tenant and user.
        builder.HasIndex(s => new { s.TenantId, s.UserId });

        // D29: the public session ID. Unique in the tenant, so one sid always names one session.
        builder.Property(s => s.Sid).HasMaxLength(22).IsFixedLength().IsRequired();
        builder.HasIndex(s => new { s.TenantId, s.Sid }).IsUnique();

        builder.Property(s => s.CreatedAt);
        builder.Property(s => s.LastSeenAt);
        builder.Property(s => s.AuthTime);
        builder.Property(s => s.AbsoluteExpiresAt);
        builder.Property(s => s.RevokedAt);

        // The purge job finds ended sessions by these columns.
        builder.HasIndex(s => s.AbsoluteExpiresAt);
        builder.HasIndex(s => s.RevokedAt).HasFilter("revoked_at IS NOT NULL");
    }
}
