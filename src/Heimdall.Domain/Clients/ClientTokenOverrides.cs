using Heimdall.Domain.Common;

namespace Heimdall.Domain.Clients;

/// <summary>Client values that replace the tenant values. A null value means: use the tenant value.</summary>
public sealed record ClientTokenOverrides
{
    public ClientTokenOverrides(TimeSpan? accessToken, TimeSpan? refreshIdle, TimeSpan? refreshAbsolute)
    {
        AccessToken = Check(accessToken, nameof(accessToken));
        RefreshIdle = Check(refreshIdle, nameof(refreshIdle));
        RefreshAbsolute = Check(refreshAbsolute, nameof(refreshAbsolute));
    }

    public static ClientTokenOverrides None { get; } = new(null, null, null);

    public TimeSpan? AccessToken { get; }

    public TimeSpan? RefreshIdle { get; }

    public TimeSpan? RefreshAbsolute { get; }

    private static TimeSpan? Check(TimeSpan? value, string name) =>
        value is null ? null : Guard.Positive(value.Value, name);
}

/// <summary>The lifetimes that apply to one client after the tenant fallback.</summary>
public sealed record TokenLifetimes(TimeSpan AccessToken, TimeSpan RefreshIdle, TimeSpan RefreshAbsolute);
