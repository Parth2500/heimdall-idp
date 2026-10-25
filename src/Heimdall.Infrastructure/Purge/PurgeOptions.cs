namespace Heimdall.Infrastructure.Purge;

/// <summary>Timing and retention for the purge job (docs/schema-design.md, "Purge job"). The values come from configuration.</summary>
public sealed class PurgeOptions
{
    public const string SectionName = "Heimdall:Purge";

    /// <summary>How often the job runs.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>The most rows that one statement deletes. Small batches keep transactions short, so /token does not wait.</summary>
    public int BatchSize { get; set; } = 1000;

    /// <summary>
    /// How long an ended family stays. A reused token of a recent family must still cause a revocation and an alert.
    /// </summary>
    public TimeSpan FamilyRetention { get; set; } = TimeSpan.FromDays(7);

    /// <summary>How long an expired code with no family stays. A replayed code must still show as redeemed for a while.</summary>
    public TimeSpan CodeRetention { get; set; } = TimeSpan.FromHours(24);

    /// <summary>How long an ended session stays, for an investigation.</summary>
    public TimeSpan SessionRetention { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// How long a back-channel logout row may stay (D35). The delivery job deletes each row after its last retry, within
    /// an hour. This limit removes the rows of a server where the job did not run.
    /// </summary>
    public TimeSpan BackchannelLogoutRetention { get; set; } = TimeSpan.FromDays(1);

    /// <summary>Checks the values. Call it at startup, so a bad configuration stops the server.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (Interval <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(Interval)}: the value must be greater than zero.");
        }

        if (BatchSize is < 1 or > 10_000)
        {
            errors.Add($"{nameof(BatchSize)}: the value must be from 1 to 10000.");
        }

        // A zero retention would remove the evidence of reuse at once.
        foreach (var (name, value) in new[]
        {
            (nameof(FamilyRetention), FamilyRetention),
            (nameof(CodeRetention), CodeRetention),
            (nameof(SessionRetention), SessionRetention),
            (nameof(BackchannelLogoutRetention), BackchannelLogoutRetention),
        })
        {
            if (value <= TimeSpan.Zero)
            {
                errors.Add($"{name}: the value must be greater than zero.");
            }
        }

        return errors;
    }
}
