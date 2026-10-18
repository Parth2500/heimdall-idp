using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Heimdall.Application.Keys;
using Heimdall.Application.UserInfo;
using Heimdall.Domain.Keys;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// Checks the format, header, and signature of an access token that a tenant signed. The keys come from
/// <see cref="ISigningKeyCache"/>, so a check reads no database.
/// </summary>
/// <remarks>
/// The rules are fixed and do not depend on the token: <c>alg</c> must be RS256 (D8), so <c>none</c> and HS256
/// confusion fail. <c>typ</c> must be <c>at+jwt</c> (RFC 9068, section 4), so an ID token cannot pass as an access
/// token. The <c>kid</c> must be in the tenant's published keys, so a key from another tenant or a removed key fails.
/// The validator never follows <c>jku</c> or <c>x5u</c>, and it rejects <c>crit</c>, because it understands no extension.
/// </remarks>
internal sealed class AccessTokenValidator : IAccessTokenValidator
{
    // An access token is well under 2 KB. The limit stops a large value before any decoding.
    private const int MaxTokenLength = 8 * 1024;

    private readonly ISigningKeyCache _keys;

    // The kid is the RFC 7638 thumbprint of the public key, so one kid always means the same key.
    private readonly ConcurrentDictionary<string, RSA> _rsaByKid = new(StringComparer.Ordinal);

    public AccessTokenValidator(ISigningKeyCache keys)
    {
        _keys = keys;
    }

    public async ValueTask<VerifiedAccessToken?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken)
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

        var header = DecodeJson(parts[0]);
        if (header is null || !TryReadHeader(header.RootElement, out var kid))
        {
            header?.Dispose();
            return null;
        }

        header.Dispose();
        var published = await _keys.GetPublishedKeysAsync(tenantId, cancellationToken).ConfigureAwait(false);
        var jwk = published.FirstOrDefault(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
        if (jwk is null || !TryDecode(parts[2], out var signature))
        {
            return null;
        }

        var rsa = _rsaByKid.GetOrAdd(jwk.Kid, _ => CreateRsa(jwk));
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        if (!rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return null;
        }

        // The payload is read only after the signature check, so every value below comes from Heimdall.
        using var payload = DecodeJson(parts[1]);
        return payload is null ? null : ReadPayload(payload.RootElement);
    }

    private static bool TryReadHeader(JsonElement header, out string kid)
    {
        kid = string.Empty;
        if (header.ValueKind != JsonValueKind.Object
            || header.TryGetProperty("crit", out _)
            || !IsString(header, "alg", out var alg) || alg != SigningKey.Algorithm
            || !IsString(header, "typ", out var typ)
            || !(typ.Equals("at+jwt", StringComparison.OrdinalIgnoreCase) || typ.Equals("application/at+jwt", StringComparison.OrdinalIgnoreCase))
            || !IsString(header, "kid", out var value))
        {
            return false;
        }

        kid = value;
        return true;
    }

    private static VerifiedAccessToken? ReadPayload(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object
            || !IsString(payload, "iss", out var iss)
            || !IsString(payload, "sub", out var sub)
            || !IsString(payload, "aud", out var aud)
            || !IsString(payload, "client_id", out var clientId)
            || !payload.TryGetProperty("exp", out var exp) || !exp.TryGetInt64(out var expSeconds))
        {
            return null;
        }

        var scopes = IsString(payload, "scope", out var scope)
            ? scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : [];
        try
        {
            return new VerifiedAccessToken(iss, sub, aud, clientId, scopes, DateTimeOffset.FromUnixTimeSeconds(expSeconds));
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static bool IsString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString()!;
        return value.Length > 0;
    }

    private static JsonDocument? DecodeJson(string segment)
    {
        if (!TryDecode(segment, out var bytes))
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // Base64url with no padding (RFC 7515, section 2). Any other character fails.
    private static bool TryDecode(string segment, out byte[] bytes)
    {
        bytes = [];
        // Base64Url.IsValid ignores white space, so each character is checked here instead.
        if (segment.Length == 0 || !segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
        {
            return false;
        }

        try
        {
            bytes = Base64Url.DecodeFromChars(segment);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
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
