using System.Text.Json;
using Heimdall.Application.Keys;
using Heimdall.Application.UserInfo;
using Heimdall.Domain.Common;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// Checks an access token that a tenant signed. <see cref="TenantJwsVerifier"/> checks the format, the header, and the
/// signature, with the keys from <see cref="ISigningKeyCache"/>, so a check reads no database.
/// </summary>
/// <remarks>
/// <c>typ</c> must be <c>at+jwt</c> (RFC 9068, section 4), so an ID token cannot pass as an access token.
/// </remarks>
internal sealed class AccessTokenValidator : IAccessTokenValidator
{
    private readonly TenantJwsVerifier _verifier;

    public AccessTokenValidator(ISigningKeyCache keys)
    {
        _verifier = new TenantJwsVerifier(keys);
    }

    public async ValueTask<VerifiedAccessToken?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken)
    {
        using var payload = await _verifier.VerifyAsync(tenantId, token, IsAccessTokenType, cancellationToken).ConfigureAwait(false);
        return payload is null ? null : ReadPayload(payload.RootElement);
    }

    private static bool IsAccessTokenType(string typ) =>
        typ.Equals("at+jwt", StringComparison.OrdinalIgnoreCase) || typ.Equals("application/at+jwt", StringComparison.OrdinalIgnoreCase);

    private static VerifiedAccessToken? ReadPayload(JsonElement payload)
    {
        if (!Jws.IsString(payload, "iss", out var iss)
            || !Jws.IsString(payload, "sub", out var sub)
            || !Jws.IsString(payload, "aud", out var aud)
            || !Jws.IsString(payload, "client_id", out var clientId)
            || !payload.TryGetProperty("exp", out var exp)
            || exp.ValueKind != JsonValueKind.Number // TryGetInt64 throws on any other kind.
            || !exp.TryGetInt64(out var expSeconds))
        {
            return null;
        }

        var scopes = Jws.IsString(payload, "scope", out var scope)
            ? scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : [];

        // RFC 9449, section 6.1: a bound token names its key in cnf.jkt. A cnf that Heimdall cannot read makes the token
        // invalid: treating it as unbound would turn a bound token into a bearer token.
        string? keyThumbprint = null;
        if (payload.TryGetProperty("cnf", out var cnf))
        {
            if (cnf.ValueKind != JsonValueKind.Object || !Jws.IsString(cnf, "jkt", out var jkt) || !KeyThumbprint.IsValid(jkt))
            {
                return null;
            }

            keyThumbprint = jkt;
        }

        // D29: the family of a user grant. Heimdall writes 32 hex digits. Any other value makes the token invalid.
        Guid? familyId = null;
        if (payload.TryGetProperty("fid", out var fid))
        {
            if (fid.ValueKind != JsonValueKind.String || !Guid.TryParseExact(fid.GetString(), "N", out var parsed))
            {
                return null;
            }

            familyId = parsed;
        }

        // Heimdall always writes iat. Only introspection reports it, and no validity rule depends on it, so a value that
        // is not a number gives no iat instead of an invalid token.
        DateTimeOffset? issuedAt = null;

        try
        {
            if (payload.TryGetProperty("iat", out var iat) && iat.ValueKind == JsonValueKind.Number && iat.TryGetInt64(out var iatSeconds))
            {
                issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatSeconds);
            }

            return new VerifiedAccessToken(iss, sub, aud, clientId, scopes, DateTimeOffset.FromUnixTimeSeconds(expSeconds), keyThumbprint, familyId, issuedAt);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
