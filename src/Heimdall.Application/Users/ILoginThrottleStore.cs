namespace Heimdall.Application.Users;

/// <summary>
/// Failed sign-ins for each account and source, in the database, so the count is exact across servers. Each write is
/// one atomic statement.
/// </summary>
public interface ILoginThrottleStore
{
    /// <summary>The end of the current wait for this account and source, or null.</summary>
    Task<DateTimeOffset?> GetThrottledUntilAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken);

    /// <summary>
    /// Adds one failure and returns the count. A count whose last failure is before <paramref name="resetBefore"/>
    /// starts again at one.
    /// </summary>
    Task<int> RecordFailureAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset now, DateTimeOffset resetBefore, CancellationToken cancellationToken);

    /// <summary>Sets the end of the wait. A later value already stored stays.</summary>
    Task ThrottleUntilAsync(Guid tenantId, Guid userId, string sourceKey, DateTimeOffset until, CancellationToken cancellationToken);

    /// <summary>After a successful sign-in from this source: its failures are forgotten.</summary>
    Task ResetAsync(Guid tenantId, Guid userId, string sourceKey, CancellationToken cancellationToken);
}
