namespace Heimdall.Infrastructure.Persistence;

/// <summary>A row in <c>dpop_proofs</c>: one DPoP proof that a tenant has seen (D26).</summary>
public sealed class DpopProofRecord
{
    public Guid TenantId { get; set; }

    /// <summary>SHA-256 of the key thumbprint and the <c>jti</c>. The same <c>jti</c> from another key is another proof.</summary>
    public byte[] ProofHash { get; set; } = [];

    /// <summary>After this time the proof fails the <c>iat</c> check anyway, so the purge job can delete the row.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
