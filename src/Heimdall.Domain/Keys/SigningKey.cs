using Heimdall.Domain.Common;

namespace Heimdall.Domain.Keys;

public enum SigningKeyStatus
{
    /// <summary>In the JWKS. Does not sign yet.</summary>
    Pending,

    /// <summary>In the JWKS. Signs new tokens. A tenant has at most one active key.</summary>
    Active,

    /// <summary>In the JWKS until <see cref="SigningKey.RemoveAfter"/>. Does not sign.</summary>
    Retired,
}

/// <summary>
/// A signing key of one tenant (D19). The private key never enters this class. It holds only a reference
/// to the key store (Key Vault, KMS, or the development file).
/// </summary>
public sealed class SigningKey
{
    public const string Algorithm = "RS256";

    private SigningKey(
        Guid id,
        Guid tenantId,
        string kid,
        string publicJwk,
        string privateKeyRef,
        DateTimeOffset publishedAt,
        DateTimeOffset signingFrom)
    {
        Id = id;
        TenantId = tenantId;
        Kid = kid;
        PublicJwk = publicJwk;
        PrivateKeyRef = privateKeyRef;
        PublishedAt = publishedAt;
        SigningFrom = signingFrom;
        Status = SigningKeyStatus.Pending;
    }

    public Guid Id { get; }

    public Guid TenantId { get; }

    public string Kid { get; }

    /// <summary>Public fields only: kty, n, e, kid, use, alg.</summary>
    public string PublicJwk { get; }

    public string PrivateKeyRef { get; }

    public SigningKeyStatus Status { get; private set; }

    public DateTimeOffset PublishedAt { get; }

    /// <summary>The earliest time this key may sign. At least one JWKS cache lifetime after publish.</summary>
    public DateTimeOffset SigningFrom { get; }

    public DateTimeOffset? RetiredAt { get; private set; }

    /// <summary>After this time the key leaves the JWKS.</summary>
    public DateTimeOffset? RemoveAfter { get; private set; }

    /// <summary>
    /// Creates a key and publishes it now. It can sign only after <paramref name="jwksCacheLifetime"/>, so every
    /// resource server cache knows the key before the first token arrives.
    /// </summary>
    public static SigningKey Create(
        Guid id,
        Guid tenantId,
        string kid,
        string publicJwk,
        string privateKeyRef,
        TimeSpan jwksCacheLifetime,
        DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.Positive(jwksCacheLifetime, nameof(jwksCacheLifetime));

        var normalizedKid = Guard.NotBlank(kid, nameof(kid));
        if (normalizedKid.Any(char.IsWhiteSpace))
        {
            throw new DomainException("A kid must not contain white space.");
        }

        var reference = Guard.NotBlank(privateKeyRef, nameof(privateKeyRef));
        if (reference.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            // A reference only. Plain key material must never reach the database.
            throw new DomainException("The private key reference must not contain key material.");
        }

        return new SigningKey(
            id,
            tenantId,
            normalizedKid,
            Guard.NotBlank(publicJwk, nameof(publicJwk)),
            reference,
            now,
            now + jwksCacheLifetime);
    }

    /// <summary>True when the key belongs in the JWKS response.</summary>
    public bool IsPublished(DateTimeOffset now) => Status switch
    {
        SigningKeyStatus.Pending or SigningKeyStatus.Active => true,
        SigningKeyStatus.Retired => RemoveAfter is { } removeAfter && now < removeAfter,
        _ => false,
    };

    public bool CanSign => Status == SigningKeyStatus.Active;

    internal void Activate(DateTimeOffset now)
    {
        if (Status != SigningKeyStatus.Pending)
        {
            throw new DomainException("Only a pending key can become active.");
        }

        if (now < SigningFrom)
        {
            throw new DomainException("The key cannot sign before every JWKS cache knows it.");
        }

        Status = SigningKeyStatus.Active;
    }

    internal void Retire(TimeSpan maxTokenLifetime, TimeSpan clockSkew, DateTimeOffset now)
    {
        if (Status != SigningKeyStatus.Active)
        {
            throw new DomainException("Only an active key can be retired.");
        }

        Status = SigningKeyStatus.Retired;
        RetiredAt = now;
        RemoveAfter = now + maxTokenLifetime + clockSkew;
    }

    /// <summary>
    /// Removes a compromised key from the JWKS at once. Tokens it signed stop working. This cost is accepted.
    /// </summary>
    public void RemoveNow(DateTimeOffset now)
    {
        Status = SigningKeyStatus.Retired;
        RetiredAt ??= now;
        RemoveAfter = now;
    }
}
