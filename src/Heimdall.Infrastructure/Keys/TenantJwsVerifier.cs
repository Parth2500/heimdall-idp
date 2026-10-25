using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// Checks the format, header, and signature of a JWT that a tenant signed, and returns its payload. The validators of
/// access tokens and of <c>id_token_hint</c> share it. The keys come from <see cref="ISigningKeyCache"/>, so a check
/// reads no database.
/// </summary>
/// <remarks>
/// The header rules are fixed and do not depend on the token: <c>alg</c> must be RS256 (D8), so <c>none</c> and HS256
/// confusion fail. The caller names the allowed <c>typ</c> values, so one kind of token cannot pass as another. The
/// <c>kid</c> must be in the tenant's published keys, so a key from another tenant or a removed key fails. The verifier
/// never follows <c>jku</c> or <c>x5u</c>, and it rejects <c>crit</c>, because it understands no extension.
/// </remarks>
internal sealed class TenantJwsVerifier
{
    // A Heimdall token is well under 2 KB. The limit stops a large value before any decoding.
    private const int MaxTokenLength = 8 * 1024;

    private readonly ISigningKeyCache _keys;

    // The kid is the RFC 7638 thumbprint of the public key, so one kid always means the same key.
    private readonly ConcurrentDictionary<string, RSA> _rsaByKid = new(StringComparer.Ordinal);

    public TenantJwsVerifier(ISigningKeyCache keys)
    {
        _keys = keys;
    }

    /// <summary>
    /// Returns the payload when the token is a compact JWS that meets every header rule, its <c>typ</c> passes
    /// <paramref name="isAllowedType"/>, and the signature is valid. Returns null on any failure. The caller disposes the
    /// document.
    /// </summary>
    public async ValueTask<JsonDocument?> VerifyAsync(
        Guid tenantId,
        string token,
        Func<string, bool> isAllowedType,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
        {
            return null;
        }

        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        string? kid;
        using (var header = Jws.DecodeJson(parts[0]))
        {
            kid = header is null ? null : ReadKid(header.RootElement, isAllowedType);
        }

        if (kid is null)
        {
            return null;
        }

        var published = await _keys.GetPublishedKeysAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var jwk = published.FirstOrDefault(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
        if (jwk is null)
        {
            return null;
        }

        var signature = Jws.Decode(parts[2]);
        if (signature is null)
        {
            return null;
        }

        var rsa = _rsaByKid.GetOrAdd(jwk.Kid, _ => CreateRsa(jwk));
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        if (!rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return null;
        }

        // The payload is read only after the signature check, so every value in it comes from Heimdall.
        var payload = Jws.DecodeJson(parts[1]);
        if (payload is { RootElement.ValueKind: JsonValueKind.Object })
        {
            return payload;
        }

        // Stryker disable once Statement : disposal frees pooled memory, and no test can observe it.
        payload?.Dispose();
        return null;
    }

    /// <summary>The <c>kid</c> when the header meets every rule, or null.</summary>
    private static string? ReadKid(JsonElement header, Func<string, bool> isAllowedType)
    {
        if (header.ValueKind != JsonValueKind.Object
            || header.TryGetProperty("crit", out _)
            || !Jws.IsString(header, "alg", out var alg) || alg != SigningKey.Algorithm
            || !Jws.IsString(header, "typ", out var typ)
            || !isAllowedType(typ))
        {
            return null;
        }

        return Jws.IsString(header, "kid", out var kid) ? kid : null;
    }

    private static RSA CreateRsa(RsaPublicJwk jwk)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64Url.DecodeFromChars(jwk.N),
            Exponent = Base64Url.DecodeFromChars(jwk.E),
        });
        return rsa;
    }
}
