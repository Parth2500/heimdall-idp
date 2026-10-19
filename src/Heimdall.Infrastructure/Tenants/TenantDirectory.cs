using Heimdall.Application.Keys;
using Heimdall.Application.Tenants;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure.Caching;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.Infrastructure.Tenants;

/// <summary>
/// Every tenant, by host, in memory (D21). One query loads the whole map, and the map expires after the server
/// cache lifetime. A request for an unknown host is answered from memory, so random host names cannot load the
/// database.
/// </summary>
internal sealed class TenantDirectory : ITenantDirectory
{
    private const byte MapKey = 0;

    private readonly IServiceScopeFactory _scopes;
    private readonly ExpiringCache<byte, IReadOnlyDictionary<string, Tenant>> _cache;

    public TenantDirectory(IServiceScopeFactory scopes, SigningKeyOptions options, TimeProvider time, HeimdallMetrics metrics)
    {
        _scopes = scopes;
        _cache = new ExpiringCache<byte, IReadOnlyDictionary<string, Tenant>>(
            _ => LoadAsync(), options.ServerCacheLifetime, time, hit => metrics.CacheLookup("tenants", hit));
    }

    public async ValueTask<Tenant?> FindByHostAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        var map = await _cache.GetAsync(MapKey, cancellationToken).ConfigureAwait(false);
        return map.GetValueOrDefault(host);
    }

    public void Invalidate() => _cache.Invalidate(MapKey);

    private async Task<IReadOnlyDictionary<string, Tenant>> LoadAsync()
    {
        var scope = _scopes.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
        {
            // The tenants table has no tenant filter: this lookup runs before the tenant is known.
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var tenants = await db.Tenants.AsNoTracking().ToListAsync(CancellationToken.None).ConfigureAwait(false);
            return tenants.ToDictionary(t => t.Host, StringComparer.Ordinal);
        }
    }
}
