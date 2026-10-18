using System.Collections.Concurrent;

namespace Heimdall.Infrastructure.Caching;

/// <summary>
/// An in-memory cache whose entries expire after a fixed lifetime. When many requests miss the same key at the
/// same time, only one of them runs the load. A failed load is not cached.
/// </summary>
internal sealed class ExpiringCache<TKey, TValue>
    where TKey : notnull
{
    private readonly Func<TKey, Task<TValue>> _load;
    private readonly TimeSpan _lifetime;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<TKey, Entry> _entries = new();

    /// <param name="load">Loads a value. It gets no cancellation token: all waiting callers share the load.</param>
    public ExpiringCache(Func<TKey, Task<TValue>> load, TimeSpan lifetime, TimeProvider time)
    {
        _load = load;
        _lifetime = lifetime;
        _time = time;
    }

    public async ValueTask<TValue> GetAsync(TKey key, CancellationToken cancellationToken)
    {
        while (true)
        {
            var now = _time.GetUtcNow();
            if (_entries.TryGetValue(key, out var entry) && entry.IsUsable(now))
            {
                return await entry.Load.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            // Lazy: only the caller that wins the swap below starts the load.
            var fresh = new Entry(new Lazy<Task<TValue>>(() => _load(key)), now + _lifetime);
            var swapped = entry is null
                ? _entries.TryAdd(key, fresh)
                : _entries.TryUpdate(key, fresh, entry);
            if (swapped)
            {
                return await fresh.Load.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public void Invalidate(TKey key) => _entries.TryRemove(key, out _);

    private sealed record Entry(Lazy<Task<TValue>> Load, DateTimeOffset ExpiresAt)
    {
        public bool IsUsable(DateTimeOffset now) =>
            now < ExpiresAt && !(Load.IsValueCreated && (Load.Value.IsFaulted || Load.Value.IsCanceled));
    }
}
