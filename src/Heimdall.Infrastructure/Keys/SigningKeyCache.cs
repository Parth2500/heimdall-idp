using System.Collections.Concurrent;
using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// The active key of each tenant, in memory for <see cref="SigningKeyOptions.ServerCacheLifetime"/>.
/// The signer reads it for each token, so a token request does not read <c>signing_keys</c>.
/// </summary>
/// <remarks>
/// A key change on this server invalidates the entry at once. A key change on another server reaches this
/// server when the entry expires. During that time this server can still sign with the previous key. Rotation
/// keeps the previous key in the JWKS, so those tokens still verify.
/// </remarks>
internal sealed class SigningKeyCache : ISigningKeyCache
{
    private readonly IServiceScopeFactory _scopes;
    private readonly SigningKeyOptions _options;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();

    public SigningKeyCache(IServiceScopeFactory scopes, SigningKeyOptions options, TimeProvider time)
    {
        _scopes = scopes;
        _options = options;
        _time = time;
    }

    public async ValueTask<ActiveSigningKey?> GetActiveKeyAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        while (true)
        {
            var now = _time.GetUtcNow();
            if (_entries.TryGetValue(tenantId, out var entry) && entry.IsUsable(now))
            {
                return await entry.Load.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            // Lazy: when many requests miss at the same time, only the winner of the swap queries the database.
            var fresh = new Entry(
                new Lazy<Task<ActiveSigningKey?>>(() => LoadAsync(tenantId)),
                now + _options.ServerCacheLifetime);

            var swapped = entry is null
                ? _entries.TryAdd(tenantId, fresh)
                : _entries.TryUpdate(tenantId, fresh, entry);
            if (swapped)
            {
                return await fresh.Load.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public void Invalidate(Guid tenantId) => _entries.TryRemove(tenantId, out _);

    // The load is shared by all waiting requests, so one caller's cancellation must not cancel it.
    private async Task<ActiveSigningKey?> LoadAsync(Guid tenantId)
    {
        var scope = _scopes.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();

            return await db.SigningKeys
                .AsNoTracking()
                .Where(k => k.TenantId == tenantId && k.Status == SigningKeyStatus.Active)
                .Select(k => new ActiveSigningKey(k.Kid, k.PrivateKeyRef))
                .SingleOrDefaultAsync(CancellationToken.None)
                .ConfigureAwait(false);
        }
    }

    private sealed record Entry(Lazy<Task<ActiveSigningKey?>> Load, DateTimeOffset ExpiresAt)
    {
        // A failed load is not cached. The next request tries again.
        public bool IsUsable(DateTimeOffset now) =>
            now < ExpiresAt && !(Load.IsValueCreated && (Load.Value.IsFaulted || Load.Value.IsCanceled));
    }
}
