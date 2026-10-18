using Heimdall.Domain.Clients;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class ClientSecretConfiguration : IEntityTypeConfiguration<ClientSecretRecord>
{
    public void Configure(EntityTypeBuilder<ClientSecretRecord> builder)
    {
        builder.ToTable("client_secrets", t =>
            t.HasCheckConstraint("ck_client_secrets_hash_length", "octet_length(secret_hash) = 32"));

        builder.HasKey(s => s.Id);
        builder.Property(s => s.Id).ValueGeneratedNever();
        builder.Property(s => s.SecretHash).HasConversion(Converters.Hash).IsRequired();

        // (tenant_id, client_pk) -> clients (tenant_id, id): a secret cannot point to another tenant's client.
        builder.HasOne<Client>()
            .WithMany()
            .HasForeignKey(s => new { s.TenantId, s.ClientPk })
            .HasPrincipalKey(c => new { c.TenantId, c.Id })
            .OnDelete(DeleteBehavior.Cascade);
    }
}
