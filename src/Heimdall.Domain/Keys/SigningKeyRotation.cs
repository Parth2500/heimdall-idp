using Heimdall.Domain.Common;

namespace Heimdall.Domain.Keys;

/// <summary>
/// Switches signing from the current key to the next one. The overlap rules are in docs/diagrams/05-keys-and-jwks.md.
/// </summary>
public static class SigningKeyRotation
{
    /// <param name="maxTokenLifetime">The longest lifetime of any token the current key signed.</param>
    /// <param name="clockSkew">The clock skew that resource servers allow.</param>
    public static void Rotate(
        SigningKey current,
        SigningKey next,
        TimeSpan maxTokenLifetime,
        TimeSpan clockSkew,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(next);
        Guard.Positive(maxTokenLifetime, nameof(maxTokenLifetime));

        if (current.TenantId != next.TenantId)
        {
            throw new DomainException("Both keys must belong to the same tenant.");
        }

        if (clockSkew < TimeSpan.Zero)
        {
            throw new DomainException("The clock skew must not be negative.");
        }

        if (current.Status != SigningKeyStatus.Active)
        {
            throw new DomainException("Only an active key can be retired.");
        }

        // Activate first. If the next key is not ready, it throws and the current key stays active.
        next.Activate(now);
        current.Retire(maxTokenLifetime, clockSkew, now);
    }

    /// <summary>Makes the first key of a tenant active. It still waits for the JWKS cache lifetime.</summary>
    public static void ActivateFirst(SigningKey key, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(key);
        key.Activate(now);
    }
}
