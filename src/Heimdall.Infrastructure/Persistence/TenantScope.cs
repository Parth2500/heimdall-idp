namespace Heimdall.Infrastructure.Persistence;

/// <summary>
/// The tenant of the current request. The Api layer sets it once, after it resolves the host (D21).
/// While it is not set, every tenant-owned query returns no rows (fail closed, D20).
/// </summary>
public sealed class TenantScope
{
    public Guid? TenantId { get; private set; }

    public void Set(Guid tenantId)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("The tenant ID must not be empty.", nameof(tenantId));
        }

        if (TenantId is { } current && current != tenantId)
        {
            throw new InvalidOperationException("The tenant of a request cannot change.");
        }

        TenantId = tenantId;
    }
}
