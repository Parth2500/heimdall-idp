using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Heimdall.Application.Keys;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// A public key from a JWK (RFC 7517) that verifies one JWS algorithm. The DPoP proofs (D25) and the client assertions
/// (D48) share it, so both have the same key rules: P-256 only for EC, 2048 to 4096 bits for RSA, and the algorithm must
/// match the key type. The caller decides which algorithms it accepts. A JWK never chooses its own algorithm.
/// </summary>
internal abstract class PublicJwk
{
    private const int MinRsaBits = 2048;
    private const int MaxRsaBits = 4096;
    private const int P256CoordinateBytes = 32;

    private PublicJwk(string thumbprint)
    {
        Thumbprint = thumbprint;
    }

    /// <summary>The RFC 7638 thumbprint of the key.</summary>
    public string Thumbprint { get; }

    /// <summary>The key for <paramref name="alg"/> (ES256, RS256, or PS256), or null when the JWK is not such a key.</summary>
    public static PublicJwk? Read(JsonElement jwk, string alg) => alg switch
    {
        "ES256" => ReadEcKey(jwk),
        "RS256" => ReadRsaKey(jwk, RSASignaturePadding.Pkcs1),
        "PS256" => ReadRsaKey(jwk, RSASignaturePadding.Pss),
        _ => null,
    };

    /// <summary>Checks the signature over the JWS signing input. False on any error. It never throws.</summary>
    public abstract bool Verify(byte[] data, byte[] signature);

    private static EcKey? ReadEcKey(JsonElement jwk)
    {
        if (!Jws.IsString(jwk, "kty", out var kty) || kty != "EC"
            || !Jws.IsString(jwk, "crv", out var crv) || crv != "P-256"
            || !Jws.IsString(jwk, "x", out var x) || Jws.Decode(x) is not { Length: P256CoordinateBytes } xBytes
            || !Jws.IsString(jwk, "y", out var y) || Jws.Decode(y) is not { Length: P256CoordinateBytes } yBytes)
        {
            return null;
        }

        // x and y are base64url, so they need no JSON escaping (RFC 7638, section 3.2).
        var thumbprint = Base64Url.EncodeToString(
            SHA256.HashData(Encoding.UTF8.GetBytes($$"""{"crv":"P-256","kty":"EC","x":"{{x}}","y":"{{y}}"}""")));
        return new EcKey(new ECPoint { X = xBytes, Y = yBytes }, thumbprint);
    }

    private static RsaKey? ReadRsaKey(JsonElement jwk, RSASignaturePadding padding)
    {
        if (!Jws.IsString(jwk, "kty", out var kty) || kty != "RSA"
            || !Jws.IsString(jwk, "n", out var n) || Jws.Decode(n) is not { } modulus
            || !Jws.IsString(jwk, "e", out var e) || Jws.Decode(e) is not { } exponent)
        {
            return null;
        }

        // RFC 7518, section 6.3.1.1: no leading zero octet, so one key has one thumbprint.
        var bits = modulus.Length * 8;
        if (modulus[0] == 0 || bits < MinRsaBits || bits > MaxRsaBits)
        {
            return null;
        }

        return new RsaKey(new RSAParameters { Modulus = modulus, Exponent = exponent }, padding, RsaPublicJwk.ComputeThumbprint(n, e));
    }

    private sealed class EcKey(ECPoint point, string thumbprint) : PublicJwk(thumbprint)
    {
        public override bool Verify(byte[] data, byte[] signature)
        {
            try
            {
                // ImportParameters refuses a point that is not on the curve.
                using var ecdsa = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = point });
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
    }

    private sealed class RsaKey(RSAParameters parameters, RSASignaturePadding padding, string thumbprint) : PublicJwk(thumbprint)
    {
        public override bool Verify(byte[] data, byte[] signature)
        {
            try
            {
                using var rsa = RSA.Create(parameters);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, padding);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
    }
}
