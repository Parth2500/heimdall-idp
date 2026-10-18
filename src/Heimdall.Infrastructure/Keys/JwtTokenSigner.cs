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

    // OpenID Connect Core: an ID token uses the plain JWT type, so it cannot pass as an access token (and the reverse).
    private const string IdTokenType = "JWT";

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

        return await SignAsync(tenantId, AccessTokenType, WritePayload(claims), cancellationToken).ConfigureAwait(false);
    }

    public async Task<string> SignIdTokenAsync(Guid tenantId, IdTokenClaims claims, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claims);
        if (claims.ExpiresAt <= claims.IssuedAt)
        {
            throw new ArgumentException("The token must expire after it is issued.", nameof(claims));
        }

        return await SignAsync(tenantId, IdTokenType, WritePayload(claims), cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> SignAsync(Guid tenantId, string type, byte[] payload, CancellationToken cancellationToken)
    {
        var key = await _keys.GetActiveKeyAsync(tenantId, cancellationToken).ConfigureAwait(false)
            ?? throw new SigningKeyUnavailableException(tenantId);

        var signingInput = Encode(WriteHeader(key.Kid, type)) + "." + Encode(payload);
        var signature = await _material
            .SignRs256Async(key.PrivateKeyRef, Encoding.ASCII.GetBytes(signingInput), cancellationToken)
            .ConfigureAwait(false);

        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    private static string Encode(ReadOnlySpan<byte> json) => Base64Url.EncodeToString(json);

    private static byte[] WriteHeader(string kid, string type) => WriteJson(writer =>
    {
        writer.WriteString("alg", SigningKey.Algorithm);
        writer.WriteString("kid", kid);
        writer.WriteString("typ", type);
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

        // RFC 9068, section 2.2.1: auth_time when the token comes from a user's sign-in.
        if (claims.AuthTime is { } authTime)
        {
            writer.WriteNumber("auth_time", authTime.ToUnixTimeSeconds());
        }
    });

    // OpenID Connect Core, section 2: iss, sub, aud, exp, iat are required. auth_time and nonce when known.
    private static byte[] WritePayload(IdTokenClaims claims) => WriteJson(writer =>
    {
        writer.WriteString("iss", claims.Issuer);
        writer.WriteString("sub", claims.Subject);
        writer.WriteString("aud", claims.ClientId);
        writer.WriteNumber("iat", claims.IssuedAt.ToUnixTimeSeconds());
        writer.WriteNumber("exp", claims.ExpiresAt.ToUnixTimeSeconds());
        writer.WriteNumber("auth_time", claims.AuthTime.ToUnixTimeSeconds());
        if (claims.Nonce is { } nonce)
        {
            writer.WriteString("nonce", nonce);
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
