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
/// <param name="SpaClientId">The public client of the demo SPA.</param>
/// <param name="SpaCreated">True when this run registered the demo SPA client.</param>
/// <param name="HuginnClientSecret">The Huginn client's secret when this run registered it, else null.</param>
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
    string? UserPassword,
    string SpaClientId,
    bool SpaCreated,
    string? HuginnClientSecret);

/// <summary>
/// Creates one tenant, a confidential client, the demo SPA client, a user, and the tenant's first signing key for
/// local development. The caller must
/// check that the environment is Development. The secret is shown once and only its hash is stored (D3).
/// Each run also activates the first key when its JWKS wait has passed.
/// </summary>
public sealed class DevelopmentSeeder
{
    public const string TenantHost = "acme.localhost";
    public const string ClientId = "demo-service";
    public const string Audience = "https://api.acme.localhost";
    public const string UserEmail = "alice@acme.localhost";

    /// <summary>The demo SPA in <c>ui/projects/demo</c> (frontend-design.md, U9 and S6).</summary>
    public const string SpaClientId = "demo-spa";
    public const string SpaRedirectUri = "https://demo.localhost:4300/callback";

    /// <summary>Where the demo SPA gets the browser back after a sign-out at Heimdall (D32).</summary>
    public const string SpaPostLogoutRedirectUri = "https://demo.localhost:4300/";

    /// <summary>
    /// Huginn, the chat app, signs in through its server (a backend-for-frontend). The redirect URI is the Angular dev
    /// server, which proxies <c>/api</c> to the Huginn API. Loopback <c>http</c> is allowed for development only.
    /// </summary>
    public const string HuginnClientId = "huginn";
    public const string HuginnRedirectUri = "http://localhost:4200/api/auth/heimdall/callback";

    /// <summary>Huginn's sign-in page, where the browser returns after a sign-out at Heimdall (D32). Heimdall adds <c>state</c>.</summary>
    public const string HuginnPostLogoutRedirectUri = "http://localhost:4200/public/login?signedOut=heimdall";

    /// <summary>
    /// The Huginn API itself, not the dev proxy: Heimdall's server calls it (D34). Loopback is allowed only in
    /// Development (D35).
    /// </summary>
    public const string HuginnBackchannelLogoutUri = "http://localhost:3000/api/auth/heimdall/backchannel-logout";
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
        var spaCreated = await EnsureSpaClientAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var huginnSecret = await EnsureHuginnClientAsync(tenantId, cancellationToken).ConfigureAwait(false);

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
            userPassword,
            SpaClientId,
            spaCreated,
            huginnSecret);
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

    /// <summary>
    /// Registers the demo SPA when it is missing, also in a database that an older seed created. Returns true when it
    /// registered it.
    /// </summary>
    private async Task<bool> EnsureSpaClientAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        if (await _db.Clients.SingleOrDefaultAsync(c => c.TenantId == tenantId && c.ClientId == SpaClientId, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            // A database from an older seed gets the sign-out URIs too.
            existing.UpdateLogoutUris([SpaPostLogoutRedirectUri], null);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }

        // A public client: no secret, PKCE on every request, and refresh tokens that rotate (U9). It has no audience,
        // so its access tokens are for /userinfo only (D22). Consent is off, so a reload of the demo gets a new code
        // with no page while the session is valid (U10).
        var client = Client.Create(
            Guid.CreateVersion7(),
            tenantId,
            SpaClientId,
            "Heimdall demo SPA",
            ClientType.Public,
            [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "email", "offline_access"],
            [SpaRedirectUri],
            requireConsent: false,
            overrides: null,
            _time.GetUtcNow());
        client.UpdateLogoutUris([SpaPostLogoutRedirectUri], null);
        client.Approve();

        _db.Clients.Add(client);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Registers the Huginn client when it is missing. Returns its new secret, or null when it already existed.
    /// </summary>
    private async Task<string?> EnsureHuginnClientAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        if (await _db.Clients.SingleOrDefaultAsync(c => c.TenantId == tenantId && c.ClientId == HuginnClientId, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            existing.UpdateLogoutUris([HuginnPostLogoutRedirectUri], HuginnBackchannelLogoutUri);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }

        // A confidential client: the secret stays on Huginn's server, and the browser never sees a Heimdall token.
        // Huginn needs only the identity at sign-in, so it has no refresh grant and no audience (D22). It keeps its own
        // session after that. Consent is off, because Huginn is a first-party app.
        var now = _time.GetUtcNow();
        var client = Client.Create(
            Guid.CreateVersion7(),
            tenantId,
            HuginnClientId,
            "Huginn",
            ClientType.Confidential,
            [GrantType.AuthorizationCode],
            ["openid", "email"],
            [HuginnRedirectUri],
            requireConsent: false,
            overrides: null,
            now);
        client.UpdateLogoutUris([HuginnPostLogoutRedirectUri], HuginnBackchannelLogoutUri);
        client.Approve();

        var secret = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        _db.Clients.Add(client);
        _db.ClientSecrets.Add(new ClientSecretRecord
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ClientPk = client.Id,
            SecretHash = TokenHash.Compute(secret),
            CreatedAt = now,
        });
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return secret;
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
