using Heimdall.Domain.Audit;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        // No foreign keys on purpose: audit rows must outlive the rows they describe.
        builder.ToTable("audit_events");

        builder.HasKey(e => e.Id);
        builder.Property(e => e.Id).ValueGeneratedNever();
        builder.Property(e => e.TenantId);
        builder.Property(e => e.OccurredAt);
        builder.Property(e => e.Type).HasMaxLength(64).IsRequired();
        builder.Property(e => e.CorrelationId).HasMaxLength(128).IsRequired();
        builder.Property(e => e.SourceIp).HasColumnType("inet");
        builder.Property(e => e.ActorUserId);
        builder.Property(e => e.SubjectUserId);
        builder.Property(e => e.ClientPk);
        builder.Property(e => e.FamilyId);
        builder.Property(e => e.Data)
            .HasColumnType("jsonb")
            .HasConversion(Converters.JsonMap, Converters.JsonMapComparer)
            .IsRequired();

        builder.HasIndex(e => new { e.TenantId, e.OccurredAt });
        builder.HasIndex(e => e.FamilyId);
    }
}
