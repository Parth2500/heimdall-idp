using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;

namespace Heimdall.Application.Clients;

/// <summary>A client with the hashes of its secrets that are valid at the time of the query.</summary>
public sealed record ClientWithSecrets(Client Client, IReadOnlyList<TokenHash> ValidSecretHashes);

public interface IClientStore
{
    /// <summary>
    /// Loads a client and its valid secret hashes in one query. One query keeps the time for a known client
    /// close to the time for an unknown client. Returns null when the client does not exist in this tenant.
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
}
