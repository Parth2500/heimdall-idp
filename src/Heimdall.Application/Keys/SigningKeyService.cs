using System.Globalization;
using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Application.Settings;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;

namespace Heimdall.Application.Keys;

/// <summary>What one maintenance pass did for a tenant.</summary>
public enum KeyMaintenanceAction
{
    None,

    /// <summary>A new pending key: the first key of the tenant, or the next key before a rotation.</summary>
    Created,

    /// <summary>The first key of the tenant became active.</summary>
    Activated,

    /// <summary>Key rotation: the next key became active and the previous key was retired.</summary>
    Rotated,
}

/// <param name="Found">False when the tenant has no key with that <c>kid</c>.</param>
/// <param name="WasActive">True when the removed key was signing. Issuance stops until a replacement is active.</param>
/// <param name="Replacement">What the service did next to restore signing.</param>
public sealed record KeyRemovalResult(bool Found, bool WasActive, KeyMaintenanceAction Replacement);

/// <summary>
/// The lifecycle of a tenant's signing keys (D19): creation, first activation, key rotation, and emergency removal.
/// The order of steps is in docs/diagrams/05-keys-and-jwks.md. Each change writes an audit event
/// (threat model, JWKS, Repudiation).
/// </summary>
/// <remarks>
/// Several servers can run these methods at the same time. The database allows one active and one pending key for
/// each tenant, and each status change is conditional on the status that was read. A server that loses a race
/// changes nothing and writes no audit event.
/// </remarks>
public sealed class SigningKeyService
{
    private readonly IKeyMaterialStore _material;
    private readonly ISigningKeyStore _keys;
    private readonly ISigningKeyCache _cache;
    private readonly IAuditLog _audit;
    private readonly SigningKeyOptions _options;
    private readonly PlatformLimits _limits;
    private readonly TimeProvider _time;

    public SigningKeyService(
        IKeyMaterialStore material,
        ISigningKeyStore keys,
        ISigningKeyCache cache,
        IAuditLog audit,
        SigningKeyOptions options,
        PlatformLimits limits,
        TimeProvider time)
    {
        _material = material;
        _keys = keys;
        _cache = cache;
        _audit = audit;
        _options = options;
        _limits = limits;
        _time = time;
    }

    /// <summary>
    /// The longest lifetime of any token a key can sign: the platform maximum, so no tenant or client setting can
    /// outlive it. A retired key stays in the JWKS this long, plus clock skew.
    /// </summary>
    private TimeSpan MaxTokenLifetime => _limits.AccessToken.Max;

    /// <summary>
    /// Creates a key pair in the key store and publishes the public key. The key is pending. It can sign only after
    /// <see cref="SigningKeyOptions.PublishWait"/>.
    /// </summary>
    /// <exception cref="ConcurrentUpdateException">The tenant already has a pending key.</exception>
    public async Task<SigningKey> CreateKeyAsync(Guid tenantId, string correlationId, CancellationToken cancellationToken)
    {
        var material = await _material.CreateRsaKeyAsync(cancellationToken).ConfigureAwait(false);
        var jwk = RsaPublicJwk.FromPublicParameters(material.N, material.E);
        var now = _time.GetUtcNow();

        var key = SigningKey.Create(
            Guid.CreateVersion7(),
            tenantId,
            jwk.Kid,
            jwk.ToJson(),
            material.PrivateKeyRef,
            _options.PublishWait,
            now);

        _keys.Add(key);
        await _keys.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _cache.Invalidate(tenantId);

        await WriteAuditAsync(key, AuditEventTypes.KeyCreated, correlationId, cancellationToken).ConfigureAwait(false);
        return key;
    }

    /// <summary>
    /// Activates the oldest pending key whose <see cref="SigningKey.SigningFrom"/> has passed, when the tenant has no
    /// active key. Returns the activated key, or null when there is nothing to do or another server was first.
    /// </summary>
    public async Task<SigningKey?> ActivateFirstKeyAsync(Guid tenantId, string correlationId, CancellationToken cancellationToken)
    {
        var keys = await _keys.ListAsync(tenantId, cancellationToken).ConfigureAwait(false);
        return keys.Any(k => k.Status == SigningKeyStatus.Active)
            ? null
            : await TryActivateAsync(keys, tenantId, correlationId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// One step toward the tenant's target state: one active key, and a next key that is ready when rotation is due.
    /// The key job calls this for each tenant that <see cref="ISigningKeyStore.ListTenantsNeedingKeyWorkAsync"/> returns.
    /// </summary>
    public async Task<KeyMaintenanceAction> MaintainAsync(Guid tenantId, string correlationId, CancellationToken cancellationToken)
    {
        var keys = await _keys.ListAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var now = _time.GetUtcNow();
        var active = keys.SingleOrDefault(k => k.Status == SigningKeyStatus.Active);
        var pending = keys.Where(k => k.Status == SigningKeyStatus.Pending).OrderBy(k => k.SigningFrom).FirstOrDefault();

        try
        {
            if (active is null)
            {
                if (pending is null)
                {
                    await CreateKeyAsync(tenantId, correlationId, cancellationToken).ConfigureAwait(false);
                    return KeyMaintenanceAction.Created;
                }

                return await TryActivateAsync(keys, tenantId, correlationId, cancellationToken).ConfigureAwait(false) is null
                    ? KeyMaintenanceAction.None
                    : KeyMaintenanceAction.Activated;
            }

            var signingFor = now - active.SigningFrom;

            // Create the next key one publish wait early, so it is ready when rotation is due.
            if (pending is null && signingFor >= _options.RotationInterval - _options.PublishWait)
            {
                await CreateKeyAsync(tenantId, correlationId, cancellationToken).ConfigureAwait(false);
                return KeyMaintenanceAction.Created;
            }

            if (pending is not null && signingFor >= _options.RotationInterval && now >= pending.SigningFrom)
            {
                await RotateAsync(active, pending, now, correlationId, cancellationToken).ConfigureAwait(false);
                return KeyMaintenanceAction.Rotated;
            }

            return KeyMaintenanceAction.None;
        }
        catch (ConcurrentUpdateException)
        {
            // Another server changed the keys first. Its change stands, and the next pass looks again.
            _cache.Invalidate(tenantId);
            return KeyMaintenanceAction.None;
        }
    }

    /// <summary>
    /// Emergency removal of a compromised key (threat model, JWKS, Elevation of privilege). The key leaves the JWKS
    /// at once, and tokens it signed stop working. This cost is accepted. When the key was active, this method starts
    /// the replacement at once: it activates a ready pending key, or creates a new one.
    /// </summary>
    /// <remarks>
    /// A new key still waits the publish wait before it signs, so token issuance stops for that time. Other servers
    /// stop signing with the removed key within one server cache lifetime.
    /// </remarks>
    public async Task<KeyRemovalResult> RemoveCompromisedKeyAsync(
        Guid tenantId,
        string kid,
        string correlationId,
        CancellationToken cancellationToken)
    {
        var keys = await _keys.ListAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var key = keys.SingleOrDefault(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
        if (key is null)
        {
            return new KeyRemovalResult(false, false, KeyMaintenanceAction.None);
        }

        var wasActive = key.Status == SigningKeyStatus.Active;
        key.RemoveNow(_time.GetUtcNow());
        await _keys.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _cache.Invalidate(tenantId);
        await WriteAuditAsync(key, AuditEventTypes.KeyRemoved, correlationId, cancellationToken).ConfigureAwait(false);

        var replacement = wasActive
            ? await MaintainAsync(tenantId, correlationId, cancellationToken).ConfigureAwait(false)
            : KeyMaintenanceAction.None;
        return new KeyRemovalResult(true, wasActive, replacement);
    }

    private async Task<SigningKey?> TryActivateAsync(
        IReadOnlyList<SigningKey> keys,
        Guid tenantId,
        string correlationId,
        CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var ready = keys
            .Where(k => k.Status == SigningKeyStatus.Pending && k.SigningFrom <= now)
            .OrderBy(k => k.SigningFrom)
            .FirstOrDefault();
        if (ready is null)
        {
            return null;
        }

        SigningKeyRotation.ActivateFirst(ready, now);
        try
        {
            await _keys.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ConcurrentUpdateException)
        {
            // Another server won. Its key is active, so this server has nothing to do or to audit.
            _cache.Invalidate(tenantId);
            return null;
        }

        _cache.Invalidate(tenantId);
        await WriteAuditAsync(ready, AuditEventTypes.KeyActivated, correlationId, cancellationToken).ConfigureAwait(false);
        return ready;
    }

    private async Task RotateAsync(
        SigningKey current,
        SigningKey next,
        DateTimeOffset now,
        string correlationId,
        CancellationToken cancellationToken)
    {
        // The Domain activates the next key before it retires the current one. Both changes save in one statement batch.
        SigningKeyRotation.Rotate(current, next, MaxTokenLifetime, _options.ClockSkew, now);
        await _keys.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _cache.Invalidate(current.TenantId);

        await WriteAuditAsync(next, AuditEventTypes.KeyActivated, correlationId, cancellationToken).ConfigureAwait(false);
        await WriteAuditAsync(current, AuditEventTypes.KeyRetired, correlationId, cancellationToken).ConfigureAwait(false);
    }

    private Task WriteAuditAsync(SigningKey key, string type, string correlationId, CancellationToken cancellationToken)
    {
        var data = new Dictionary<string, string>
        {
            ["kid"] = key.Kid,
            ["signing_from"] = Format(key.SigningFrom),
        };
        if (key.RemoveAfter is { } removeAfter)
        {
            data["remove_after"] = Format(removeAfter);
        }

        return _audit.WriteAsync(
            AuditEvent.Record(Guid.CreateVersion7(), key.TenantId, type, correlationId, _time.GetUtcNow(), data: data),
            cancellationToken);
    }

    // Microseconds, the precision that PostgreSQL stores, so the audit value equals the stored value.
    private static string Format(DateTimeOffset value) =>
        value.AddTicks(-(value.Ticks % 10)).ToString("yyyy-MM-ddTHH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
}
