namespace Heimdall.Application.Keys;

/// <summary>Timing for signing keys. The values come from configuration.</summary>
public sealed class SigningKeyOptions
{
    public const string SectionName = "Heimdall:SigningKeys";

    /// <summary>
    /// The JWKS <c>max-age</c>. A new key waits this long before it signs, so every resource server cache knows it
    /// before the first token arrives (threat model, JWKS, Elevation of privilege).
    /// </summary>
    public TimeSpan JwksCacheLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long one server keeps a tenant's key set in memory. A key change on another server reaches this server
    /// within this time. Emergency removal is therefore not instant on every server.
    /// </summary>
    public TimeSpan ServerCacheLifetime { get; set; } = TimeSpan.FromMinutes(1);

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

        return errors;
    }
}
