using Heimdall.Domain.Users;

namespace Heimdall.Application.Users;

/// <summary>The <c>users</c> table of one tenant.</summary>
public interface IUserStore
{
    /// <summary>The user with this normalized email in the tenant, tracked for change, or null.</summary>
    Task<User?> FindByEmailAsync(Guid tenantId, string emailNormalized, CancellationToken cancellationToken);

    /// <summary>The user with this ID in the tenant, or null.</summary>
    Task<User?> FindByIdAsync(Guid tenantId, Guid userId, CancellationToken cancellationToken);

    void Add(User user);

    /// <summary>Saves the changes. A second user with the same email in the tenant throws a ConcurrentUpdateException.</summary>
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
