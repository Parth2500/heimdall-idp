namespace Heimdall.Application.Users;

/// <summary>The sign-in throttle for each account and source (<see cref="Domain.Users.LoginThrottle"/>). From configuration.</summary>
public sealed class LoginThrottleOptions
{
    public const string SectionName = "Heimdall:LoginThrottle";

    /// <summary>Failures in a row that cost nothing. A user who mistypes a few times is never slowed.</summary>
    public int FreeFailures { get; set; } = 5;

    /// <summary>The longest wait. The wait doubles with each failure after the free ones, up to this value.</summary>
    public TimeSpan MaxDelay { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>A source with no failure for this long starts again from zero. The purge job then deletes its row.</summary>
    public TimeSpan ResetAfter { get; set; } = TimeSpan.FromHours(24);

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (FreeFailures < 1)
        {
            errors.Add($"{nameof(FreeFailures)}: the value must be at least 1.");
        }

        if (MaxDelay <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(MaxDelay)}: the value must be greater than zero.");
        }

        if (ResetAfter <= MaxDelay)
        {
            errors.Add($"{nameof(ResetAfter)}: the value must be longer than {nameof(MaxDelay)}.");
        }

        return errors;
    }
}
