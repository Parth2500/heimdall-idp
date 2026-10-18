using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Heimdall.Infrastructure.Persistence.Configurations;

internal sealed class AuthorizationRequestConfiguration : IEntityTypeConfiguration<AuthorizationRequest>
{
    public void Configure(EntityTypeBuilder<AuthorizationRequest> builder)
    {
        builder.ToTable("authorization_requests", t =>
        {
            t.HasCheckConstraint("ck_authorization_requests_max_age", "max_age_seconds IS NULL OR max_age_seconds >= 0");
            t.HasCheckConstraint(
                "ck_authorization_requests_consent",
                "(consent_user_id IS NULL) = (consent_approved IS NULL)");
        });

        builder.HasKey(r => r.Id);
        builder.Property(r => r.Id).ValueGeneratedNever();
        builder.HasOne<Tenant>().WithMany().HasForeignKey(r => r.TenantId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Client>().WithMany().HasForeignKey(r => r.ClientPk).OnDelete(DeleteBehavior.Cascade);

        builder.Property(r => r.RedirectUri).HasMaxLength(2048).IsRequired();
        builder.Property(r => r.Scope).HasMaxLength(1024).IsRequired();
        builder.Property(r => r.State).HasMaxLength(AuthorizationRequest.MaxClientValueLength);
        builder.Property(r => r.Nonce).HasMaxLength(AuthorizationRequest.MaxClientValueLength);

        // code_challenge_method is always S256, so it has no column (D2).
        builder.Property(r => r.CodeChallenge).HasMaxLength(43).IsFixedLength().IsRequired();
        builder.Property(r => r.ForceLogin);
        builder.Property(r => r.MaxAge).HasColumnName("max_age_seconds").HasConversion(Converters.Seconds);
        builder.Property(r => r.CreatedAt);
        builder.Property(r => r.ExpiresAt);
        builder.Property(r => r.ConsentUserId);
        builder.Property(r => r.ConsentApproved);

        // The purge job deletes expired requests.
        builder.HasIndex(r => r.ExpiresAt);
    }
}
