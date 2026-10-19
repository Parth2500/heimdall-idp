using System.Collections.Frozen;
using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Infrastructure.Caching;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.Infrastructure.Stores;

/// <summary>
/// The client store of one request. It serves from <see cref="ClientCache"/> only for the tenant of the request's
/// <see cref="TenantScope"/>. A lookup for another tenant, or with no tenant, returns null (fail closed, D20), as the
/// query filter did before the cache.
/// </summary>
internal sealed class EfClientStore : IClientStore
{
    private readonly ClientCache _cache;
    private readonly TenantScope _scope;

    public EfClientStore(ClientCache cache, TenantScope scope)
    {
        _cache = cache;
        _scope = scope;
    }

    public Task<ClientWithSecrets?> FindForAuthenticationAsync(Guid tenantId, string clientId, DateTimeOffset now, CancellationToken cancellationToken) =>
        IsRequestTenant(tenantId) ? _cache.FindForAuthenticationAsync(tenantId, clientId, now, cancellationToken) : Task.FromResult<ClientWithSecrets?>(null);

    public Task<Client?> FindAsync(Guid tenantId, string clientId, CancellationToken cancellationToken) =>
        IsRequestTenant(tenantId) ? _cache.FindAsync(tenantId, clientId, cancellationToken) : Task.FromResult<Client?>(null);

    public Task<Client?> FindByPkAsync(Guid tenantId, Guid clientPk, CancellationToken cancellationToken) =>
        IsRequestTenant(tenantId) ? _cache.FindByPkAsync(tenantId, clientPk, cancellationToken) : Task.FromResult<Client?>(null);

    public Task<bool> IsBrowserOriginAllowedAsync(Guid tenantId, string origin, CancellationToken cancellationToken) =>
        IsRequestTenant(tenantId) ? _cache.IsBrowserOriginAllowedAsync(tenantId, origin, cancellationToken) : Task.FromResult(false);

    public void Invalidate(Guid tenantId) => _cache.Invalidate(tenantId);

    private bool IsRequestTenant(Guid tenantId) => _scope.TenantId == tenantId;
}

/// <summary>
/// The clients of each tenant, in memory for <see cref="SigningKeyOptions.ServerCacheLifetime"/>. One query loads all
/// clients of a tenant with their unrevoked secrets. A request for an unknown <c>client_id</c> is answered from
/// memory, so random client IDs cannot load the database, and the cache size depends on the stored clients only.
/// </summary>
/// <remarks>
/// A change on this server calls <see cref="Invalidate"/> and takes effect at once. A change on another server takes
/// effect here when the entry expires: a disabled client or a revoked secret can still work for up to one server cache
/// lifetime. Secret expiry is checked at each read, so it is exact.
/// </remarks>
internal sealed class ClientCache
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ExpiringCache<Guid, TenantClients> _cache;

    public ClientCache(IServiceScopeFactory scopes, SigningKeyOptions options, TimeProvider time, HeimdallMetrics metrics)
    {
        _scopes = scopes;
        _cache = new ExpiringCache<Guid, TenantClients>(LoadAsync, options.ServerCacheLifetime, time, hit => metrics.CacheLookup("clients", hit));
    }

    public async Task<ClientWithSecrets?> FindForAuthenticationAsync(
        Guid tenantId,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var clients = await _cache.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        if (!clients.ByClientId.TryGetValue(clientId, out var entry))
        {
            return null;
        }

        var valid = entry.Secrets.Where(s => s.ExpiresAt is not { } expiresAt || expiresAt > now).Select(s => s.Hash).ToList();
        return new ClientWithSecrets(entry.Client, valid);
    }

    public async Task<Client?> FindAsync(Guid tenantId, string clientId, CancellationToken cancellationToken)
    {
        var clients = await _cache.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        return clients.ByClientId.GetValueOrDefault(clientId)?.Client;
    }

    public async Task<Client?> FindByPkAsync(Guid tenantId, Guid clientPk, CancellationToken cancellationToken)
    {
        var clients = await _cache.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        return clients.ByPk.GetValueOrDefault(clientPk)?.Client;
    }

    public async Task<bool> IsBrowserOriginAllowedAsync(Guid tenantId, string origin, CancellationToken cancellationToken)
    {
        var clients = await _cache.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        return clients.BrowserOrigins.Contains(origin);
    }

    public void Invalidate(Guid tenantId) => _cache.Invalidate(tenantId);

    private async Task<TenantClients> LoadAsync(Guid tenantId)
    {
        var scope = _scopes.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
        {
            // The tenant scope sets the query filter and the row-level security setting (D20).
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();

            var clients = await db.Clients.AsNoTracking().Where(c => c.TenantId == tenantId)
                .ToListAsync(CancellationToken.None).ConfigureAwait(false);
            var secrets = await db.ClientSecrets.AsNoTracking()
                .Where(s => s.TenantId == tenantId && s.RevokedAt == null)
                .Select(s => new { s.ClientPk, s.SecretHash, s.ExpiresAt })
                .ToListAsync(CancellationToken.None).ConfigureAwait(false);

            var secretsByClient = secrets.ToLookup(s => s.ClientPk);
            var entries = clients
                .Select(c => new CachedClient(c, secretsByClient[c.Id].Select(s => new CachedSecret(s.SecretHash, s.ExpiresAt)).ToList()))
                .ToList();
            return new TenantClients(
                entries.ToDictionary(e => e.Client.ClientId, StringComparer.Ordinal),
                entries.ToDictionary(e => e.Client.Id),
                clients.SelectMany(c => c.BrowserOrigins()).ToFrozenSet(StringComparer.Ordinal));
        }
    }

    private sealed record CachedSecret(TokenHash Hash, DateTimeOffset? ExpiresAt);

    private sealed record CachedClient(Client Client, IReadOnlyList<CachedSecret> Secrets);

    private sealed record TenantClients(
        IReadOnlyDictionary<string, CachedClient> ByClientId,
        IReadOnlyDictionary<Guid, CachedClient> ByPk,
        FrozenSet<string> BrowserOrigins);
}
