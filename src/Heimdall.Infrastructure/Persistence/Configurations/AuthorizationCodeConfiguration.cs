using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
{
    public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
    {
        builder.ToTable("authorization_codes");

        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(c => c.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Client>().WithMany().HasForeignKey(c => c.ClientPk).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<User>().WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Restrict);

        // The redemption looks the code up by its hash. Unique, so one hash can never match two rows.
        builder.Property(c => c.CodeHash).HasConversion(Converters.Hash).HasMaxLength(32);
        builder.HasIndex(c => new { c.TenantId, c.CodeHash }).IsUnique();

        builder.Property(c => c.RedirectUri).HasMaxLength(2048).IsRequired();
        builder.Property(c => c.Scope).HasMaxLength(1024).IsRequired();
        builder.Property(c => c.CodeChallenge).HasMaxLength(43).IsFixedLength().IsRequired();
        builder.Property(c => c.Nonce).HasMaxLength(AuthorizationRequest.MaxClientValueLength);
        builder.Property(c => c.AuthTime);
        builder.Property(c => c.CreatedAt);
        builder.Property(c => c.ExpiresAt);
        builder.Property(c => c.RedeemedAt);

        // ON DELETE SET NULL: a code survives its family for the purge delay (docs/schema-design.md, "Purge job").
        // The migration makes this key DEFERRABLE INITIALLY DEFERRED: the redemption UPDATE sets family_id before the
        // family row is inserted in the same transaction, and the check runs at commit.
        builder.HasOne<TokenFamily>().WithMany().HasForeignKey(c => c.FamilyId).OnDelete(DeleteBehavior.SetNull);

        // The purge job deletes expired codes with no family.
        builder.HasIndex(c => c.ExpiresAt).HasFilter("family_id IS NULL");
    }
}
