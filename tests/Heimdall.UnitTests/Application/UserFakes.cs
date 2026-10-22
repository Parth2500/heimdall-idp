using Heimdall.Application.Users;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Application;

/// <summary>A test fake. It keeps users in memory.</summary>
internal sealed class InMemoryUserStore : IUserStore
{
    public List<User> Users { get; } = [];

    public int SaveCount { get; private set; }

    public Task<User?> FindByEmailAsync(Guid tenantId, string emailNormalized, CancellationToken cancellationToken) =>
        Task.FromResult(Users.SingleOrDefault(u => u.TenantId == tenantId && u.EmailNormalized == emailNormalized));

    public Task<User?> FindByIdAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken) =>
        Task.FromResult(Users.SingleOrDefault(u => u.TenantId == tenantId && u.Id == userId));

    public void Add(User user) => Users.Add(user);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        SaveCount++;
        return Task.CompletedTask;
    }
}

internal sealed class InMemoryLoginThrottleStore : ILoginThrottleStore
{
    public Dictionary<(Guid Tenant, Guid User, string Source), (int Failures, DateTimeOffset Last, DateTimeOffset? Until)> Rows { get; } = [];

    public Task<DateTimeOffset?> GetThrottledUntilAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken) =>
        Task.FromResult(Rows.TryGetValue((tenantId, userId, sourceKey), out var row) ? row.Until : null);

    public Task<int> RecordFailureAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset now, DateTimeOffset resetBefore, CancellationToken cancellationToken)
    {
        var key = (tenantId, userId, sourceKey);
        var row = Rows.TryGetValue(key, out var existing) && existing.Last >= resetBefore
            ? (existing.Failures + 1, now, existing.Until)
            : (1, now, (DateTimeOffset?)null);
        Rows[key] = row;
        return Task.FromResult(row.Item1);
    }

    public Task ThrottleUntilAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset until, CancellationToken cancellationToken)
    {
        var key = (tenantId, userId, sourceKey);
        var row = Rows[key];
        Rows[key] = (row.Failures, row.Last, row.Until is { } current && current > until ? current : until);
        return Task.CompletedTask;
    }

    public Task ResetAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken)
    {
        Rows.Remove((tenantId, userId, sourceKey));
        return Task.CompletedTask;
    }
}

/// <summary>Records every verification. A "hash" is the password with a prefix, so tests stay fast.</summary>
internal sealed class FakePasswordHasher : IPasswordHasher
{
    public List<string?> Verified { get; } = [];

    public bool ReportNeedsRehash { get; set; }

    public bool Busy { get; set; }

    public static string HashOf(string password) => "fake:" + password;

    public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken) =>
        ValueTask.FromResult(HashOf(password) + ":v2");

    public ValueTask<PasswordCheck> VerifyAsync(string? hash, string password, CancellationToken cancellationToken)
    {
        if (Busy)
        {
            throw new PasswordHasherBusyException();
        }

        Verified.Add(hash);
        var verified = hash is not null && hash == HashOf(password);
        return ValueTask.FromResult(new PasswordCheck(verified, verified && ReportNeedsRehash));
    }
}
