using Heimdall.Domain.Common;

namespace Heimdall.Domain.Users;

/// <summary>
/// The backoff for failed sign-ins of one account from one source (CLAUDE.md, abuse principles). It throttles and never
/// locks: a delay ends by itself, and failures from one source do not slow the account at another source.
/// </summary>
public static class LoginThrottle
{
    /// <summary>
    /// The wait after <paramref name="failures"/> failures in a row. The first <paramref name="freeFailures"/> cost
    /// nothing, so a user who mistypes a few times is never slowed. After that, the wait doubles with each failure:
    /// 1 s, 2 s, 4 s, and so on, up to <paramref name="maxDelay"/>. Returns null when no wait applies.
    /// </summary>
    public static TimeSpan? DelayAfter(int failures, int freeFailures, TimeSpan maxDelay)
    {
        if (freeFailures < 0)
        {
            throw new DomainException("The number of free failures must not be negative.");
        }

        Guard.Positive(maxDelay, nameof(maxDelay));

        var over = failures - freeFailures;
        if (over <= 0)
        {
            return null;
        }

        // 2^30 seconds is decades, so a larger exponent changes nothing and cannot overflow.
        var seconds = Math.Pow(2, Math.Min(over - 1, 30));
        return TimeSpan.FromSeconds(Math.Min(seconds, maxDelay.TotalSeconds));
    }
}
