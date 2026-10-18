using Heimdall.Domain.Common;

namespace Heimdall.Domain.Tenants;

/// <summary>
/// Lifetimes that apply to a tenant. Clients use the token lifetimes unless they override them (D15).
/// The platform minimum and maximum are checked in the Application layer (D16).
/// </summary>
public sealed record TenantSettings
{
    public TenantSettings(
        TimeSpan sessionIdle,
        TimeSpan sessionAbsolute,
        TimeSpan accessToken,
        TimeSpan refreshIdle,
        TimeSpan refreshAbsolute)
    {
        SessionIdle = Guard.Positive(sessionIdle, nameof(sessionIdle));
        SessionAbsolute = Guard.Positive(sessionAbsolute, nameof(sessionAbsolute));
        AccessToken = Guard.Positive(accessToken, nameof(accessToken));
        RefreshIdle = Guard.Positive(refreshIdle, nameof(refreshIdle));
        RefreshAbsolute = Guard.Positive(refreshAbsolute, nameof(refreshAbsolute));

        if (SessionIdle > SessionAbsolute)
        {
            throw new DomainException("The session idle timeout must not be longer than the absolute lifetime.");
        }

        if (RefreshIdle > RefreshAbsolute)
        {
            throw new DomainException("The refresh idle timeout must not be longer than the absolute lifetime.");
        }
    }

    public TimeSpan SessionIdle { get; }

    public TimeSpan SessionAbsolute { get; }

    public TimeSpan AccessToken { get; }

    public TimeSpan RefreshIdle { get; }

    public TimeSpan RefreshAbsolute { get; }

    /// <summary>The platform defaults from docs/threat-model.md.</summary>
    public static TenantSettings Default { get; } = new(
        sessionIdle: TimeSpan.FromMinutes(30),
        sessionAbsolute: TimeSpan.FromHours(12),
        accessToken: TimeSpan.FromMinutes(5),
        refreshIdle: TimeSpan.FromDays(7),
        refreshAbsolute: TimeSpan.FromDays(30));
}
