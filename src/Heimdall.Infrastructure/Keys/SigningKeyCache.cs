using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Caching;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// The key set of each tenant, in memory for <see cref="SigningKeyOptions.ServerCacheLifetime"/>. The signer and the
/// JWKS read it, so neither a token request nor a JWKS request reads <c>signing_keys</c>.
/// </summary>
/// <remarks>
/// A key change on this server invalidates the entry at once. A key change on another server reaches this server
/// when the entry expires. <see cref="SigningKeyOptions.PublishWait"/> includes this delay.
/// </remarks>
internal sealed class SigningKeyCache : ISigningKeyCache
{
    private readonly IServiceScopeFactory _scopes;
    private readonly TimeProvider _time;
    private readonly ExpiringCache<Guid, TenantKeySet> _cache;

    public SigningKeyCache(IServiceScopeFactory scopes, SigningKeyOptions options, TimeProvider time)
    {
        _scopes = scopes;
        _time = time;
        _cache = new ExpiringCache<Guid, TenantKeySet>(LoadAsync, options.ServerCacheLifetime, time);
    }

    public async ValueTask<ActiveSigningKey?> GetActiveKeyAsync(Guid tenantId, CancellationToken cancellationToken) =>
        (await _cache.GetAsync(tenantId, cancellationToken).ConfigureAwait(false)).Active;

    public async ValueTask<IReadOnlyList<RsaPublicJwk>> GetPublishedKeysAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        var set = await _cache.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);

        // A retired key leaves the JWKS at remove_after. The check runs on each read, not only on each load.
        var now = _time.GetUtcNow();
        return set.Published
            .Where(k => k.RemoveAfter is not { } removeAfter || now < removeAfter)
            .Select(k => k.Jwk)
            .ToList();
    }

    public void Invalidate(Guid tenantId) => _cache.Invalidate(tenantId);

    private async Task<TenantKeySet> LoadAsync(Guid tenantId)
    {
        var scope = _scopes.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();

            var now = _time.GetUtcNow();
            var keys = await db.SigningKeys
                .AsNoTracking()
                .Where(k => k.TenantId == tenantId)
                .ToListAsync(CancellationToken.None)
                .ConfigureAwait(false);

            var active = keys.SingleOrDefault(k => k.CanSign);
            var published = keys
                .Where(k => k.IsPublished(now))
                .OrderBy(k => k.PublishedAt)
                .Select(k => new PublishedKey(RsaPublicJwk.FromJson(k.PublicJwk), k.Status == SigningKeyStatus.Retired ? k.RemoveAfter : null))
                .ToList();

            return new TenantKeySet(active is null ? null : new ActiveSigningKey(active.Kid, active.PrivateKeyRef), published);
        }
    }

    private sealed record PublishedKey(RsaPublicJwk Jwk, DateTimeOffset? RemoveAfter);

    private sealed record TenantKeySet(ActiveSigningKey? Active, IReadOnlyList<PublishedKey> Published);
}
