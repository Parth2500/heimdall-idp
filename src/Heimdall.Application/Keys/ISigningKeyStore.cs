using Heimdall.Domain.Keys;

namespace Heimdall.Application.Keys;

/// <summary>The <c>signing_keys</c> rows of one tenant. Key material is in <see cref="IKeyMaterialStore"/>.</summary>
public interface ISigningKeyStore
{
    /// <summary>All keys of the tenant, tracked for change.</summary>
    Task<IReadOnlyList<SigningKey>> ListAsync(Guid tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The tenants that have no active key but have a pending key whose wait has ended. This is a platform query
    /// across tenants, for the activation job only.
    /// </summary>
    Task<IReadOnlyList<Guid>> ListTenantsAwaitingActivationAsync(DateTimeOffset now, CancellationToken cancellationToken);

    void Add(SigningKey key);

    /// <summary>
    /// Saves the changes. The database allows one active key for each tenant. When a concurrent caller activated a
    /// key first, this throws <see cref="Common.ConcurrentUpdateException"/> and saves nothing.
    /// </summary>
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

/// <param name="Kid">The key identifier for the JWT header.</param>
/// <param name="PrivateKeyRef">The reference that <see cref="IKeyMaterialStore"/> signs with.</param>
public sealed record ActiveSigningKey(string Kid, string PrivateKeyRef);

/// <summary>
/// The key set of each tenant, in memory. The signer and the JWKS read it, so they do not read the database
/// for each request.
/// </summary>
public interface ISigningKeyCache
{
    /// <summary>The key that signs new tokens, or null when the tenant has no active key.</summary>
    ValueTask<ActiveSigningKey?> GetActiveKeyAsync(Guid tenantId, CancellationToken cancellationToken);

    /// <summary>The public keys that belong in the tenant's JWKS now: pending, active, and retired before removal.</summary>
    ValueTask<IReadOnlyList<RsaPublicJwk>> GetPublishedKeysAsync(Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Drops the tenant's key set on this server. The next read loads it again.</summary>
    void Invalidate(Guid tenantId);
}
