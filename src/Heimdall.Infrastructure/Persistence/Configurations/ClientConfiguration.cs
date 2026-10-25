using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class ClientConfiguration : IEntityTypeConfiguration<Client>
{
    public void Configure(EntityTypeBuilder<Client> builder)
    {
        const string bound = TenantConfiguration.SecondsBound;

        // The database repeats the most important Domain rules, as the last defense against a bug.
        builder.ToTable("clients", t =>
        {
            t.HasCheckConstraint("ck_clients_type", "type IN ('public', 'confidential')");
            t.HasCheckConstraint("ck_clients_status", "status IN ('pending', 'active', 'disabled')");
            t.HasCheckConstraint(
                "ck_clients_grant_types",
                "cardinality(allowed_grant_types) > 0 AND allowed_grant_types " +
                "<@ ARRAY['authorization_code', 'client_credentials', 'refresh_token']::text[]");
            t.HasCheckConstraint(
                "ck_clients_auth_method",
                "(type = 'public' AND token_endpoint_auth_method = 'none') " +
                "OR (type = 'confidential' AND token_endpoint_auth_method = 'client_secret_basic')");
            t.HasCheckConstraint(
                "ck_clients_client_credentials_confidential",
                "NOT ('client_credentials' = ANY (allowed_grant_types)) OR type = 'confidential'");
            t.HasCheckConstraint(
                "ck_clients_client_credentials_audience",
                "NOT ('client_credentials' = ANY (allowed_grant_types)) OR cardinality(allowed_audiences) > 0");
            t.HasCheckConstraint(
                "ck_clients_resource_audiences_confidential",
                "cardinality(resource_audiences) = 0 OR type = 'confidential'");
            t.HasCheckConstraint(
                "ck_clients_lifetimes",
                $"(access_token_seconds IS NULL OR access_token_seconds {bound}) " +
                $"AND (refresh_idle_seconds IS NULL OR refresh_idle_seconds {bound}) " +
                $"AND (refresh_absolute_seconds IS NULL OR refresh_absolute_seconds {bound})");
        });

        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id).ValueGeneratedNever();

        // Composite key target, so child tables can use (tenant_id, client_pk) foreign keys (D20).
        builder.HasAlternateKey(c => new { c.TenantId, c.Id });
        builder.HasOne<Tenant>().WithMany().HasForeignKey(c => c.TenantId).OnDelete(DeleteBehavior.Restrict);

        builder.Property(c => c.ClientId).HasMaxLength(128).IsRequired();
        builder.HasIndex(c => new { c.TenantId, c.ClientId }).IsUnique();
        builder.Property(c => c.Name).HasMaxLength(200).IsRequired();
        builder.Property(c => c.Type).HasConversion(new SnakeCaseEnumConverter<ClientType>()).HasMaxLength(32);
        builder.Property(c => c.TokenEndpointAuthMethod)
            .HasConversion(new SnakeCaseEnumConverter<TokenEndpointAuthMethod>())
            .HasMaxLength(32);
        builder.Property(c => c.Status).HasConversion(new SnakeCaseEnumConverter<ClientStatus>()).HasMaxLength(32);
        builder.Property(c => c.RequireConsent);
        builder.Property(c => c.RequireDpop);
        builder.Property(c => c.CreatedAt);

        builder.PrimitiveCollection(c => c.AllowedGrantTypes)
            .HasField("_allowedGrantTypes")
            .UsePropertyAccessMode(PropertyAccessMode.Field)
            .ElementType(e => e.HasConversion(new SnakeCaseEnumConverter<GrantType>()));
        builder.PrimitiveCollection(c => c.AllowedScopes)
            .HasField("_allowedScopes")
            .UsePropertyAccessMode(PropertyAccessMode.Field);
        builder.PrimitiveCollection(c => c.RedirectUris)
            .HasField("_redirectUris")
            .UsePropertyAccessMode(PropertyAccessMode.Field);
        builder.PrimitiveCollection(c => c.AllowedAudiences)
            .HasField("_allowedAudiences")
            .UsePropertyAccessMode(PropertyAccessMode.Field);
        builder.PrimitiveCollection(c => c.PostLogoutRedirectUris)
            .HasField("_postLogoutRedirectUris")
            .UsePropertyAccessMode(PropertyAccessMode.Field);
        builder.Property(c => c.BackchannelLogoutUri).HasMaxLength(2048);
        builder.PrimitiveCollection(c => c.ResourceAudiences)
            .HasField("_resourceAudiences")
            .UsePropertyAccessMode(PropertyAccessMode.Field);

        builder.Ignore(c => c.RefreshEnabled);

        // A complex property is a value without identity, so two clients can share one instance.
        // All three columns null means "use the tenant value" (D15).
        builder.ComplexProperty(c => c.TokenOverrides, o =>
        {
            o.Property(p => p.AccessToken).HasColumnName("access_token_seconds").HasConversion(Converters.Seconds);
            o.Property(p => p.RefreshIdle).HasColumnName("refresh_idle_seconds").HasConversion(Converters.Seconds);
            o.Property(p => p.RefreshAbsolute).HasColumnName("refresh_absolute_seconds").HasConversion(Converters.Seconds);
        });
    }
}
