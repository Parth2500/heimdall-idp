namespace Heimdall.Application.Keys;

/// <summary>Timing for signing keys. The values come from configuration.</summary>
public sealed class SigningKeyOptions
{
    public const string SectionName = "Heimdall:SigningKeys";

    /// <summary>The JWKS <c>max-age</c>. Resource servers and proxies can cache the key set this long.</summary>
    public TimeSpan JwksCacheLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long one server keeps a tenant's key set in memory. A key change on another server reaches this server
    /// within this time. Emergency removal is therefore not instant on every server.
    /// </summary>
    public TimeSpan ServerCacheLifetime { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How often the activation job looks for pending keys whose wait has ended.</summary>
    public TimeSpan ActivationCheckInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How long a key signs before the next key replaces it.</summary>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// The clock difference that resource servers allow when they check <c>exp</c>. A retired key stays in the JWKS
    /// this much longer than its last token.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long a new key waits before it signs. Another server can serve the old JWKS for one server cache lifetime,
    /// and a resource server can then cache that JWKS for one JWKS cache lifetime. The wait covers both, so every
    /// cache knows the key before the first token arrives (threat model, JWKS, Elevation of privilege).
    /// </summary>
    public TimeSpan PublishWait => JwksCacheLifetime + ServerCacheLifetime;

    /// <summary>Checks the values. Call it at startup, so a bad configuration stops the server.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (JwksCacheLifetime <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(JwksCacheLifetime)}: the value must be greater than zero.");
        }

        if (ServerCacheLifetime <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(ServerCacheLifetime)}: the value must be greater than zero.");
        }

        if (ActivationCheckInterval <= TimeSpan.Zero)
        {
            errors.Add($"{nameof(ActivationCheckInterval)}: the value must be greater than zero.");
        }

        // The next key is created one publish wait before rotation. A shorter interval would never let it get ready.
        if (RotationInterval <= PublishWait)
        {
            errors.Add($"{nameof(RotationInterval)}: the value must be longer than the publish wait ({PublishWait}).");
        }

        if (ClockSkew < TimeSpan.Zero)
        {
            errors.Add($"{nameof(ClockSkew)}: the value must not be negative.");
        }

        return errors;
    }
}
