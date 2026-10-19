namespace Heimdall.Infrastructure.Persistence;

/// <summary>A row in <c>login_throttles</c>: the failed sign-ins of one account from one source.</summary>
public sealed class LoginThrottleRecord
{
    public Guid TenantId { get; set; }

    public Guid UserId { get; set; }

    /// <summary>The source key (<see cref="Application.Common.SourceKeys"/>): an IPv4 address or an IPv6 /64 network.</summary>
    public string SourceKey { get; set; } = string.Empty;

    public int Failures { get; set; }

    public DateTimeOffset LastFailureAt { get; set; }

    public DateTimeOffset? ThrottledUntil { get; set; }
}
