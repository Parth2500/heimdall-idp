using System.Text.RegularExpressions;
using Heimdall.Domain.Common;

namespace Heimdall.Domain.Tenants;

public enum TenantStatus
{
    Active,
    Suspended,
}

/// <summary>An isolated domain with its own users, clients, keys, and settings (D19).</summary>
public sealed class Tenant
{
    // Lowercase DNS labels separated by dots. No wildcards, no underscores.
    private static readonly Regex HostPattern = new(
        "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private Tenant(
        Guid id,
        string host,
        string name,
        TenantSettings settings,
        TenantStatus status,
        DateTimeOffset createdAt)
    {
        Id = id;
        Host = host;
        Name = name;
        Settings = settings;
        Status = status;
        CreatedAt = createdAt;
    }

    public Guid Id { get; }

    /// <summary>The host name that selects this tenant (D21). Always lowercase.</summary>
    public string Host { get; }

    public string Name { get; private set; }

    public TenantSettings Settings { get; private set; }

    public TenantStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; }

    public static Tenant Create(Guid id, string host, string name, TenantSettings settings, DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        ArgumentNullException.ThrowIfNull(settings);

        var normalizedHost = Guard.NotBlank(host, nameof(host)).ToLowerInvariant();
        if (!HostPattern.IsMatch(normalizedHost))
        {
            throw new DomainException("The tenant host is not a valid host name.");
        }

        return new Tenant(id, normalizedHost, Guard.NotBlank(name, nameof(name)), settings, TenantStatus.Active, now);
    }

    public void UpdateSettings(TenantSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Settings = settings;
    }

    public void Suspend() => Status = TenantStatus.Suspended;

    public void Activate() => Status = TenantStatus.Active;
}
