namespace Heimdall.Infrastructure.Persistence;

/// <summary>A row in <c>client_assertions</c>: one <c>private_key_jwt</c> assertion that a client has used (D49).</summary>
public sealed class ClientAssertionRecord
{
    public Guid TenantId { get; set; }

    /// <summary>SHA-256 of the client's primary key and the <c>jti</c>. The same <c>jti</c> from another client is another assertion.</summary>
    public byte[] AssertionHash { get; set; } = [];

    /// <summary>After this time the assertion fails the <c>exp</c> check anyway, so the purge job can delete the row.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
