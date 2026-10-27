using Heimdall.Domain.Common;
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

    /// <summary>
    /// D42: one conditional UPDATE takes a pushed request for <c>/authorize</c>. It matches only an unexpired request
    /// with this <c>request_uri</c> hash for this client. It clears the hash, so the same <c>request_uri</c> never works
    /// twice, and it moves <c>expires_at</c> to <see cref="AuthorizationRequest.Lifetime"/> after <paramref name="now"/>
    /// for the sign-in pages. Returns the request, tracked for change, or null when no row matched. A request_uri sent
    /// with another client_id matches no row, so it cannot burn the real client's request.
    /// </summary>
    Task<AuthorizationRequest?> TakePushedRequestAsync(
        Guid tenantId,
        TokenHash requestUriHash,
        Guid clientPk,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    void AddCode(AuthorizationCode code);

    /// <summary>
    /// Saves the changes in one transaction. When another caller removed the same request first, this throws
    /// <see cref="Common.ConcurrentUpdateException"/> and saves nothing, so one request never gives two codes.
    /// </summary>
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
