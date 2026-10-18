using Heimdall.Application.Audit;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;

namespace Heimdall.Application.Keys;

/// <summary>
/// Creates the signing keys of a tenant and activates the first one (D19). Rotation of an active key is a later step.
/// Each change writes an audit event (threat model, JWKS, Repudiation).
/// </summary>
public sealed class SigningKeyService
{
    private readonly IKeyMaterialStore _material;
    private readonly ISigningKeyStore _keys;
    private readonly ISigningKeyCache _cache;
    private readonly IAuditLog _audit;
    private readonly SigningKeyOptions _options;
    private readonly TimeProvider _time;

    public SigningKeyService(
        IKeyMaterialStore material,
        ISigningKeyStore keys,
        ISigningKeyCache cache,
        IAuditLog audit,
        SigningKeyOptions options,
        TimeProvider time)
    {
        _material = material;
        _keys = keys;
        _cache = cache;
        _audit = audit;
        _options = options;
        _time = time;
    }

    /// <summary>
    /// Creates a key pair in the key store and publishes the public key. The key is pending. It can sign only after
    /// one JWKS cache lifetime.
    /// </summary>
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
            _options.JwksCacheLifetime,
            now);

        _keys.Add(key);
        await _keys.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _cache.Invalidate(tenantId);

        await WriteAuditAsync(key, AuditEventTypes.KeyCreated, correlationId, cancellationToken).ConfigureAwait(false);
        return key;
    }

    /// <summary>
    /// Activates the oldest pending key whose <see cref="SigningKey.SigningFrom"/> has passed, when the tenant has no
    /// active key. Returns the activated key, or null when there is nothing to do.
    /// </summary>
    public async Task<SigningKey?> ActivateFirstKeyAsync(Guid tenantId, string correlationId, CancellationToken cancellationToken)
    {
        var keys = await _keys.ListAsync(tenantId, cancellationToken).ConfigureAwait(false);
        if (keys.Any(k => k.Status == SigningKeyStatus.Active))
        {
            return null;
        }

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
        await _keys.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _cache.Invalidate(tenantId);

        await WriteAuditAsync(ready, AuditEventTypes.KeyActivated, correlationId, cancellationToken).ConfigureAwait(false);
        return ready;
    }

    private Task WriteAuditAsync(SigningKey key, string type, string correlationId, CancellationToken cancellationToken) =>
        _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                key.TenantId,
                type,
                correlationId,
                _time.GetUtcNow(),
                data: new Dictionary<string, string>
                {
                    ["kid"] = key.Kid,
                    ["signing_from"] = key.SigningFrom.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                }),
            cancellationToken);
}
