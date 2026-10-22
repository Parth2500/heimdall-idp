using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;

namespace Heimdall.Application.Sessions;

/// <summary>The <c>sessions</c> table of one tenant. Rows are found by the hash of the session ID (D12).</summary>
public interface ISessionStore
{
    /// <summary>The session with this ID hash in the tenant, tracked for change, or null.</summary>
    Task<Session?> FindAsync(Guid tenantId, TokenHash idHash, CancellationToken cancellationToken);

    /// <summary>
    /// The session and its user in one query, both tracked for change, or null when either is missing. Session
    /// validation runs on many requests, so it costs one round trip, not two.
    /// </summary>
    Task<(Session Session, User User)?> FindWithUserAsync(Guid tenantId, TokenHash idHash, CancellationToken cancellationToken);

    void Add(Session session);

    Task SaveChangesAsync(CancellationToken cancellationToken);
}
