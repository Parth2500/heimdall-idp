using System.Buffers.Text;
using System.Security.Cryptography;
using Heimdall.Application.Keys;
using Heimdall.Application.Users;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Keys;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Development;

/// <param name="Created">False when the data already existed. The secret is then not known and is null.</param>
/// <param name="Kid">The tenant's newest signing key.</param>
/// <param name="KeyStatus">The status of that key after this run.</param>
/// <param name="SigningFrom">The earliest time that key can sign.</param>
/// <param name="UserEmail">The development user.</param>
/// <param name="UserPassword">The user's password when this run created the user, else null.</param>
public sealed record SeedResult(
    bool Created,
    string TenantHost,
    string ClientId,
    string? ClientSecret,
    string Audience,
    string Kid,
    SigningKeyStatus KeyStatus,
    DateTimeOffset SigningFrom,
    string UserEmail,
    string? UserPassword);

/// <summary>
/// Creates one tenant, one client, and the tenant's first signing key for local development. The caller must
/// check that the environment is Development. The secret is shown once and only its hash is stored (D3).
/// Each run also activates the first key when its JWKS wait has passed.
/// </summary>
public sealed class DevelopmentSeeder
{
    public const string TenantHost = "acme.localhost";
    public const string ClientId = "demo-service";
    public const string Audience = "https://api.acme.localhost";
    public const string UserEmail = "alice@acme.localhost";
    private const string CorrelationId = "seed-dev";

    private readonly HeimdallDbContext _db;
    private readonly TenantScope _scope;
    private readonly SigningKeyService _keyService;
    private readonly ISigningKeyStore _keys;
    private readonly IUserStore _users;
    private readonly IPasswordHasher _hasher;
    private readonly TimeProvider _time;

    public DevelopmentSeeder(
        HeimdallDbContext db,
        TenantScope scope,
        SigningKeyService keyService,
        ISigningKeyStore keys,
        IUserStore users,
        IPasswordHasher hasher,
        TimeProvider time)
    {
        _db = db;
        _scope = scope;
        _keyService = keyService;
        _keys = keys;
        _users = users;
        _hasher = hasher;
        _time = time;
    }

    public async Task<SeedResult> SeedAsync(CancellationToken cancellationToken)
    {
        await _db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);

        var existing = await _db.Tenants
            .AsNoTracking()
            .Where(t => t.Host == TenantHost)
            .Select(t => (Guid?)t.Id)
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        string? secret = null;
        Guid tenantId;
        if (existing is { } id)
        {
            tenantId = id;
            _scope.Set(tenantId);
        }
        else
        {
            (tenantId, secret) = await CreateTenantAndClientAsync(cancellationToken).ConfigureAwait(false);
        }

        var userPassword = await EnsureUserAsync(tenantId, cancellationToken).ConfigureAwait(false);

        // Creates the first key, or activates it when its wait has ended. The running server's key job does the same.
        await _keyService.MaintainAsync(tenantId, CorrelationId, cancellationToken).ConfigureAwait(false);

        var newest = (await _keys.ListAsync(tenantId, cancellationToken).ConfigureAwait(false))
            .OrderByDescending(k => k.PublishedAt)
            .First();

        return new SeedResult(
            existing is null,
            TenantHost,
            ClientId,
            secret,
            Audience,
            newest.Kid,
            newest.Status,
            newest.SigningFrom,
            UserEmail,
            userPassword);
    }

    /// <summary>Creates the development user when it is missing. Returns its new password, or null.</summary>
    private async Task<string?> EnsureUserAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        if (await _users.FindByEmailAsync(tenantId, User.NormalizeEmail(UserEmail), cancellationToken).ConfigureAwait(false) is not null)
        {
            return null;
        }

        // 24 random bytes give a 32-character password, inside the D14 length limits.
        var password = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(24));
        var hash = await _hasher.HashAsync(password, cancellationToken).ConfigureAwait(false);
        _users.Add(User.Create(Guid.CreateVersion7(), tenantId, UserEmail, hash, _time.GetUtcNow()));
        await _users.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return password;
    }

    private async Task<(Guid TenantId, string Secret)> CreateTenantAndClientAsync(CancellationToken cancellationToken)
    {
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

        return (tenant.Id, secret);
    }
}
