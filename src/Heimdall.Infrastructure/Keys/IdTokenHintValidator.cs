using System.Text.Json;
using Heimdall.Application.Keys;
using Heimdall.Application.Logout;
using Heimdall.Domain.Sessions;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// Checks an <c>id_token_hint</c> (D30). <see cref="TenantJwsVerifier"/> checks the format, the header, and the signature
/// with the tenant's published keys, so a retired key still counts until it leaves the JWKS.
/// </summary>
/// <remarks>
/// <c>typ</c> must be <c>JWT</c>, the type that <see cref="JwtTokenSigner"/> writes for an ID token. An access token
/// (<c>at+jwt</c>) or a logout token (<c>logout+jwt</c>) is not a hint. <c>exp</c> is not read: a client usually sends an
/// expired ID token at sign-out, and the hint only names the client and the session.
/// </remarks>
internal sealed class IdTokenHintValidator : IIdTokenHintValidator
{
    private readonly TenantJwsVerifier _verifier;

    public IdTokenHintValidator(ISigningKeyCache keys)
    {
        _verifier = new TenantJwsVerifier(keys);
    }

    public async ValueTask<VerifiedIdTokenHint?> ValidateAsync(Guid tenantId, string token, CancellationToken cancellationToken)
    {
        using var payload = await _verifier.VerifyAsync(tenantId, token, IsIdTokenType, cancellationToken).ConfigureAwait(false);
        return payload is null ? null : ReadPayload(payload.RootElement);
    }

    private static bool IsIdTokenType(string typ) => typ.Equals("JWT", StringComparison.OrdinalIgnoreCase);

    private static VerifiedIdTokenHint? ReadPayload(JsonElement payload)
    {
        if (!Jws.IsString(payload, "iss", out var iss)
            || !Jws.IsString(payload, "sub", out var sub)
            || ReadAudiences(payload) is not { Count: > 0 } audiences)
        {
            return null;
        }

        // A sid that is not one of Heimdall's makes the hint name no session. It cannot end one at once (D31).
        string? sid = null;
        if (payload.TryGetProperty("sid", out _))
        {
            if (!Jws.IsString(payload, "sid", out var value) || !SessionSid.IsValid(value))
            {
                return null;
            }

            sid = value;
        }

        return new VerifiedIdTokenHint(iss, sub, audiences, sid);
    }

    /// <summary>OpenID Connect Core, section 2: <c>aud</c> is one string or an array of strings.</summary>
    private static List<string>? ReadAudiences(JsonElement payload)
    {
        if (!payload.TryGetProperty("aud", out var aud))
        {
            return null;
        }

        if (aud.ValueKind == JsonValueKind.String)
        {
            return aud.GetString() is { Length: > 0 } single ? [single] : null;
        }

        if (aud.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var values = new List<string>();
        foreach (var item in aud.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { Length: > 0 } value)
            {
                return null;
            }

            values.Add(value);
        }

        return values;
    }
}
