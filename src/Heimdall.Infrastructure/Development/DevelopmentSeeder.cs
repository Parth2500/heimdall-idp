using System.Buffers.Text;
using System.Security.Cryptography;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Development;

/// <param name="Created">False when the data already existed. The secret is then not known and is null.</param>
public sealed record SeedResult(bool Created, string TenantHost, string ClientId, string? ClientSecret, string Audience);

/// <summary>
/// Creates one tenant and one client for local development. The caller must check that the environment is
/// Development. The secret is shown once and only its hash is stored (D3).
/// </summary>
public sealed class DevelopmentSeeder
{
    public const string TenantHost = "acme.localhost";
    public const string ClientId = "demo-service";
    public const string Audience = "https://api.acme.localhost";

    private readonly HeimdallDbContext _db;
    private readonly TenantScope _scope;
    private readonly TimeProvider _time;

    public DevelopmentSeeder(HeimdallDbContext db, TenantScope scope, TimeProvider time)
    {
        _db = db;
        _scope = scope;
        _time = time;
    }

    public async Task<SeedResult> SeedAsync(CancellationToken cancellationToken)
    {
        await _db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);

        if (await _db.Tenants.AnyAsync(t => t.Host == TenantHost, cancellationToken).ConfigureAwait(false))
        {
            return new SeedResult(false, TenantHost, ClientId, null, Audience);
        }

        var now = _time.GetUtcNow();
        var tenant = Tenant.Create(Guid.CreateVersion7(), TenantHost, "Acme (development)", TenantSettings.Default, now);
        _scope.Set(tenant.Id);

        var client = Client.Create(
            Guid.CreateVersion7(),
            tenant.Id,
            ClientId,
            "Demo service",
            ClientType.Confidential,
            [GrantType.ClientCredentials],
            ["demo.read"],
            [],
            requireConsent: false,
            overrides: null,
            now,
            [Audience]);
        client.Approve();

        var secret = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        _db.Tenants.Add(tenant);
        _db.Clients.Add(client);
        _db.ClientSecrets.Add(new ClientSecretRecord
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenant.Id,
            ClientPk = client.Id,
            SecretHash = TokenHash.Compute(secret),
            CreatedAt = now,
        });
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return new SeedResult(true, TenantHost, ClientId, secret, Audience);
    }
}
