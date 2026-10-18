using Heimdall.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class TenantConfiguration : IEntityTypeConfiguration<Tenant>
{
    // Outer bounds only (400 days). The tighter platform limits are in configuration (D16).
    internal const string SecondsBound = "BETWEEN 1 AND 34560000";

    public void Configure(EntityTypeBuilder<Tenant> builder)
    {
        builder.ToTable("tenants", t =>
        {
            t.HasCheckConstraint("ck_tenants_status", "status IN ('active', 'suspended')");
            t.HasCheckConstraint(
                "ck_tenants_lifetimes",
                $"session_idle_seconds {SecondsBound} AND session_absolute_seconds {SecondsBound} " +
                $"AND access_token_seconds {SecondsBound} AND refresh_idle_seconds {SecondsBound} " +
                $"AND refresh_absolute_seconds {SecondsBound}");
        });

        builder.HasKey(t => t.Id);
        builder.Property(t => t.Id).ValueGeneratedNever();
        builder.Property(t => t.Host).HasMaxLength(253).IsRequired();
        builder.HasIndex(t => t.Host).IsUnique();
        builder.Property(t => t.Name).HasMaxLength(200).IsRequired();
        builder.Property(t => t.Status).HasConversion(new SnakeCaseEnumConverter<TenantStatus>()).HasMaxLength(32);
        builder.Property(t => t.CreatedAt);

        // A complex property, not an owned entity: EF Core tracks an owned entity by reference,
        // so tenants that share TenantSettings.Default in one SaveChanges would lose their values.
        builder.ComplexProperty(t => t.Settings, s =>
        {
            s.Property(p => p.SessionIdle).HasColumnName("session_idle_seconds").HasConversion(Converters.Seconds);
            s.Property(p => p.SessionAbsolute).HasColumnName("session_absolute_seconds").HasConversion(Converters.Seconds);
            s.Property(p => p.AccessToken).HasColumnName("access_token_seconds").HasConversion(Converters.Seconds);
            s.Property(p => p.RefreshIdle).HasColumnName("refresh_idle_seconds").HasConversion(Converters.Seconds);
            s.Property(p => p.RefreshAbsolute).HasColumnName("refresh_absolute_seconds").HasConversion(Converters.Seconds);
        });
    }
}
