using System.Buffers;
using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Keys;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// Creates RFC 9068 access tokens: a compact JWS with <c>alg</c> = RS256, <c>kid</c>, and <c>typ</c> = <c>at+jwt</c> (D8).
/// </summary>
/// <remarks>
/// Heimdall writes the JWT itself and does not use a JWT library to sign. The key store signs the bytes, which a
/// non-exportable Key Vault or KMS key requires. The header is fixed, so no input can change <c>alg</c>.
/// The tests check each token with an independent JWT library.
/// </remarks>
internal sealed class JwtTokenSigner : ITokenSigner
{
    private const string AccessTokenType = "at+jwt";

    private readonly ISigningKeyCache _keys;
    private readonly IKeyMaterialStore _material;

    public JwtTokenSigner(ISigningKeyCache keys, IKeyMaterialStore material)
    {
        _keys = keys;
        _material = material;
    }

    public async Task<string> SignAccessTokenAsync(Guid tenantId, AccessTokenClaims claims, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claims);
        if (claims.ExpiresAt <= claims.IssuedAt)
        {
            throw new ArgumentException("The token must expire after it is issued.", nameof(claims));
        }

        var key = await _keys.GetActiveKeyAsync(tenantId, cancellationToken).ConfigureAwait(false)
            ?? throw new SigningKeyUnavailableException(tenantId);

        var signingInput = Encode(WriteHeader(key.Kid)) + "." + Encode(WritePayload(claims));
        var signature = await _material
            .SignRs256Async(key.PrivateKeyRef, Encoding.ASCII.GetBytes(signingInput), cancellationToken)
            .ConfigureAwait(false);

        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    private static string Encode(ReadOnlySpan<byte> json) => Base64Url.EncodeToString(json);

    private static byte[] WriteHeader(string kid) => WriteJson(writer =>
    {
        writer.WriteString("alg", SigningKey.Algorithm);
        writer.WriteString("kid", kid);
        writer.WriteString("typ", AccessTokenType);
    });

    // RFC 9068, section 2.2: iss, exp, aud, sub, client_id, iat, and jti are required. scope is added when present.
    private static byte[] WritePayload(AccessTokenClaims claims) => WriteJson(writer =>
    {
        writer.WriteString("iss", claims.Issuer);
        writer.WriteString("sub", claims.Subject);
        writer.WriteString("aud", claims.Audience);
        writer.WriteString("client_id", claims.ClientId);
        writer.WriteNumber("iat", claims.IssuedAt.ToUnixTimeSeconds());
        writer.WriteNumber("exp", claims.ExpiresAt.ToUnixTimeSeconds());
        writer.WriteString("jti", claims.JwtId);
        if (claims.Scopes.Count > 0)
        {
            writer.WriteString("scope", string.Join(' ', claims.Scopes));
        }
    });

    private static byte[] WriteJson(Action<Utf8JsonWriter> writeProperties)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writeProperties(writer);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }
}
