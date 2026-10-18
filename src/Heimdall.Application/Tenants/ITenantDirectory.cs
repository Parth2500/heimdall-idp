using Heimdall.Domain.Tenants;

namespace Heimdall.Application.Tenants;

/// <summary>
/// Finds the tenant of a request from its host name (D21). The implementation holds every host in memory, so a
/// request for an unknown host never reaches the database.
/// </summary>
public interface ITenantDirectory
{
    /// <summary>The tenant for a normalized host (lowercase, no port), or null.</summary>
    /// <remarks>Treat the returned tenant as read-only. Other requests share the same instance.</remarks>
    ValueTask<Tenant?> FindByHostAsync(string host, CancellationToken cancellationToken);

    /// <summary>Drops the host map on this server. The next lookup loads it again.</summary>
    void Invalidate();
}
