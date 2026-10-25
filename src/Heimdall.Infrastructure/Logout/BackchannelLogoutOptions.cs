namespace Heimdall.Infrastructure.Logout;

/// <summary>Timing of the back-channel logout delivery (D35). The values come from configuration.</summary>
public sealed class BackchannelLogoutOptions
{
    public const string SectionName = "Heimdall:BackchannelLogout";

    /// <summary>The name of the HTTP client that sends the logout tokens.</summary>
    public const string HttpClientName = "Heimdall.BackchannelLogout";

    /// <summary>How often the job looks for due rows.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>D35: the time limit of one call, from connect to the response headers.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>D35: the retries after the first call. After the last one fails, the row is dropped.</summary>
    public int MaxRetries { get; set; } = 5;

    /// <summary>The wait before the first retry. Each later wait is twice the one before.</summary>
    public TimeSpan FirstRetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The most rows that one pass takes. The calls of one pass run at the same time.</summary>
    public int BatchSize { get; set; } = 16;

    /// <summary>
    /// D35: refuse loopback, private, and link-local addresses. Program.cs turns it off in Development only, so a local
    /// client on <c>localhost</c> works there.
    /// </summary>
    public bool BlockPrivateAddresses { get; set; } = true;

    /// <summary>The lifetime of a logout token (D34): 2 minutes after <c>iat</c>.</summary>
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(2);

    /// <summary>
    /// How long a taken row stays with its server. It is longer than one pass, so no other server sends the row twice,
    /// and short, so a crashed server's rows come back soon.
    /// </summary>
    public TimeSpan Lease => Timeout * 4;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (Interval <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(Interval)}: the value must be greater than zero.");
        }

        if (Timeout < TimeSpan.FromSeconds(1) || Timeout > TimeSpan.FromSeconds(30))
        {
            errors.Add($"{nameof(Timeout)}: the value must be from 1 to 30 seconds.");
        }

        if (MaxRetries is < 0 or > 10)
        {
            errors.Add($"{nameof(MaxRetries)}: the value must be from 0 to 10.");
        }

        if (FirstRetryDelay <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(FirstRetryDelay)}: the value must be greater than zero.");
        }

        if (BatchSize is < 1 or > 100)
        {
            errors.Add($"{nameof(BatchSize)}: the value must be from 1 to 100.");
        }

        return errors;
    }
}
