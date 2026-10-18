namespace Heimdall.Application.Keys;

/// <param name="PrivateKeyRef">The store's reference to the private key. It is not key material.</param>
/// <param name="N">The RSA modulus, base64url.</param>
/// <param name="E">The RSA public exponent, base64url.</param>
public sealed record CreatedKeyMaterial(string PrivateKeyRef, string N, string E);

/// <summary>
/// Holds private signing keys: Key Vault or KMS on deployment, the development key file locally.
/// The private key never leaves the store. Heimdall sends the bytes to sign and gets the signature back.
/// This matches a non-exportable key in Key Vault or KMS, so the signing code does not change on deployment.
/// </summary>
public interface IKeyMaterialStore
{
    /// <summary>Creates an RSA key pair in the store and returns its reference and public parameters.</summary>
    Task<CreatedKeyMaterial> CreateRsaKeyAsync(CancellationToken cancellationToken);

    /// <summary>Signs <paramref name="data"/> with RSASSA-PKCS1-v1_5 and SHA-256 (RS256).</summary>
    Task<byte[]> SignRs256Async(string privateKeyRef, ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
}
