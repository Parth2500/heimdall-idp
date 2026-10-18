namespace Heimdall.Application.Settings;

/// <summary>The smallest and largest value that a tenant or client may set (D16).</summary>
public sealed class DurationLimit
{
    public DurationLimit()
    {
    }

    public DurationLimit(TimeSpan min, TimeSpan max)
    {
        Min = min;
        Max = max;
    }

    public TimeSpan Min { get; set; }

    public TimeSpan Max { get; set; }

    public bool Contains(TimeSpan value) => value >= Min && value <= Max;

    public override string ToString() => $"{Min} to {Max}";
}

/// <summary>
/// Platform limits for tenant and client settings (D15, D16). The values come from configuration.
/// The defaults below are the starting values in docs/threat-model.md, "Limits and lifetimes".
/// </summary>
public sealed class PlatformLimits
{
    public const string SectionName = "Heimdall:PlatformLimits";

    public DurationLimit SessionIdle { get; set; } = new(TimeSpan.FromMinutes(5), TimeSpan.FromHours(24));

    public DurationLimit SessionAbsolute { get; set; } = new(TimeSpan.FromHours(1), TimeSpan.FromDays(30));

    public DurationLimit AccessToken { get; set; } = new(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(60));

    public DurationLimit RefreshIdle { get; set; } = new(TimeSpan.FromHours(1), TimeSpan.FromDays(30));

    public DurationLimit RefreshAbsolute { get; set; } = new(TimeSpan.FromDays(1), TimeSpan.FromDays(90));

    /// <summary>Checks the limits themselves. Call it at startup, so a bad configuration stops the server.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        Check(nameof(SessionIdle), SessionIdle);
        Check(nameof(SessionAbsolute), SessionAbsolute);
        Check(nameof(AccessToken), AccessToken);
        Check(nameof(RefreshIdle), RefreshIdle);
        Check(nameof(RefreshAbsolute), RefreshAbsolute);
        return errors;

        void Check(string name, DurationLimit? limit)
        {
            if (limit is null)
            {
                errors.Add($"{name}: the limit is missing.");
            }
            else if (limit.Min <= TimeSpan.Zero)
            {
                errors.Add($"{name}: the minimum must be greater than zero.");
            }
            else if (limit.Min > limit.Max)
            {
                errors.Add($"{name}: the minimum must not be greater than the maximum.");
            }
        }
    }
}
