using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Authorization;

/// <summary>
/// Stored <c>/authorize</c> requests and issued codes. One store, because issuing a code and removing its request
/// must save in one transaction.
/// </summary>
public interface IAuthorizationStore
{
    void AddRequest(AuthorizationRequest request);

    /// <summary>The stored request with this ID in the tenant, tracked for change, or null.</summary>
    Task<AuthorizationRequest?> FindRequestAsync(Guid tenantId, Guid requestId, CancellationToken cancellationToken);

    void RemoveRequest(AuthorizationRequest request);

    void AddCode(AuthorizationCode code);

    /// <summary>
    /// Saves the changes in one transaction. When another caller removed the same request first, this throws
    /// <see cref="Common.ConcurrentUpdateException"/> and saves nothing, so one request never gives two codes.
    /// </summary>
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
