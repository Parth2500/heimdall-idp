using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;

namespace Heimdall.Application.Clients;

/// <summary>A client with the hashes of its secrets that are valid at the time of the query.</summary>
public sealed record ClientWithSecrets(Client Client, IReadOnlyList<TokenHash> ValidSecretHashes);

/// <summary>
/// The clients of a tenant, read-only. The implementation keeps each tenant's clients in memory, so a request for a
/// known or an unknown client never reaches the database (CLAUDE.md, performance principles).
/// </summary>
/// <remarks>Treat a returned client as read-only. Other requests share the same instance.</remarks>
public interface IClientStore
{
    /// <summary>
    /// A client and its secret hashes that are valid at <paramref name="now"/>. A known and an unknown client take
    /// the same path, a lookup in memory. Returns null when the client does not exist in this tenant.
    /// </summary>
    Task<ClientWithSecrets?> FindForAuthenticationAsync(
        Guid tenantId,
        string clientId,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>The client with this public ID in the tenant, without secrets, or null.</summary>
    Task<Client?> FindAsync(Guid tenantId, string clientId, CancellationToken cancellationToken);

    /// <summary>The client with this primary key in the tenant, without secrets, or null.</summary>
    Task<Client?> FindByPkAsync(Guid tenantId, Guid clientPk, CancellationToken cancellationToken);

    /// <summary>
    /// Drops the tenant's clients on this server. Call it after a change to a client or a secret. Other servers see the
    /// change when their entry expires, within the server cache lifetime.
    /// </summary>
    void Invalidate(Guid tenantId);
}
