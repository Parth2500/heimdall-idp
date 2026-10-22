namespace Heimdall.Application.Dpop;

/// <summary>Remembers each DPoP proof until it is too old to pass the <c>iat</c> check (D26).</summary>
public interface IDpopReplayStore
{
    /// <summary>
    /// One atomic statement. True when the proof is new. False when the same key already used this <c>jti</c> in the
    /// tenant: a replay. Two servers that see one proof at the same time get one true and one false.
    /// </summary>
    Task<bool> TryUseAsync(Guid tenantId, DpopProof proof, CancellationToken cancellationToken);
}
