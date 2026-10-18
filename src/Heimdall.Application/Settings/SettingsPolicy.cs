using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;

namespace Heimdall.Application.Settings;

/// <summary>
/// Checks tenant and client settings against the platform limits before an admin saves them (D16).
/// The Domain layer already rejects zero values and idle longer than absolute. This class adds the ranges.
/// </summary>
public sealed class SettingsPolicy
{
    private readonly PlatformLimits _limits;

    public SettingsPolicy(PlatformLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);

        var problems = limits.Validate();
        if (problems.Count > 0)
        {
            throw new ArgumentException("The platform limits are not valid: " + string.Join(" ", problems), nameof(limits));
        }

        _limits = limits;
    }

    public IReadOnlyList<string> Validate(TenantSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var errors = new List<string>();
        Check(errors, "Session idle timeout", settings.SessionIdle, _limits.SessionIdle);
        Check(errors, "Session absolute lifetime", settings.SessionAbsolute, _limits.SessionAbsolute);
        Check(errors, "Access token lifetime", settings.AccessToken, _limits.AccessToken);
        Check(errors, "Refresh idle timeout", settings.RefreshIdle, _limits.RefreshIdle);
        Check(errors, "Refresh absolute lifetime", settings.RefreshAbsolute, _limits.RefreshAbsolute);
        return errors;
    }

    /// <summary>Checks only the values that the client sets. A null value uses the tenant value.</summary>
    public IReadOnlyList<string> Validate(ClientTokenOverrides overrides)
    {
        ArgumentNullException.ThrowIfNull(overrides);

        var errors = new List<string>();
        Check(errors, "Access token lifetime", overrides.AccessToken, _limits.AccessToken);
        Check(errors, "Refresh idle timeout", overrides.RefreshIdle, _limits.RefreshIdle);
        Check(errors, "Refresh absolute lifetime", overrides.RefreshAbsolute, _limits.RefreshAbsolute);
        return errors;
    }

    private static void Check(List<string> errors, string name, TimeSpan? value, DurationLimit limit)
    {
        if (value is { } v && !limit.Contains(v))
        {
            errors.Add($"{name} must be from {limit}.");
        }
    }
}
