using System.Text.Json;
using Heimdall.Domain.Common;

namespace Heimdall.Domain.Clients;

/// <summary>
/// The registration rules for a client's public keys (<c>jwks</c>, D46). Only the shape is checked here. The key
/// material itself is checked when an assertion is verified, so a bad key can never verify a signature.
/// </summary>
internal static class ClientJwksRules
{
    /// <summary>A JWK Set with five RSA-4096 keys is under 4 KB. The limit stops a large value in the database.</summary>
    public const int MaxLength = 16 * 1024;

    /// <summary>Enough for a rotation overlap. A long list makes every failed check try more keys.</summary>
    public const int MaxKeys = 5;

    public const int MaxKidLength = 128;

    // Members of a private JWK (RFC 7518, section 6). A key with one of them is a private key: a registration mistake that
    // would put the client's secret into Heimdall's database.
    private static readonly string[] PrivateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    /// <summary>Returns the JWK Set unchanged, or throws <see cref="DomainException"/>.</summary>
    public static string Validate(string? jwks)
    {
        if (string.IsNullOrWhiteSpace(jwks) || jwks.Length > MaxLength)
        {
            throw new DomainException($"The jwks must be a JSON object of at most {MaxLength} characters.");
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(jwks);
        }
        catch (JsonException)
        {
            throw new DomainException("The jwks is not valid JSON.");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("keys", out var keys)
                || keys.ValueKind != JsonValueKind.Array
                || keys.GetArrayLength() is 0 or > MaxKeys)
            {
                throw new DomainException($"The jwks needs a \"keys\" array with 1 to {MaxKeys} keys.");
            }

            var kids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var key in keys.EnumerateArray())
            {
                ValidateKey(key, kids);
            }
        }

        return jwks;
    }

    private static void ValidateKey(JsonElement key, HashSet<string> kids)
    {
        if (key.ValueKind != JsonValueKind.Object)
        {
            throw new DomainException("Each key in the jwks must be a JSON object.");
        }

        if (PrivateMembers.Any(member => key.TryGetProperty(member, out _)))
        {
            throw new DomainException("The jwks holds a private key. Register only the public keys.");
        }

        // The assertion names its key with kid, so a check tries one key, not all of them.
        if (!key.TryGetProperty("kid", out var kid) || kid.ValueKind != JsonValueKind.String
            || kid.GetString() is not { Length: > 0 and <= MaxKidLength } kidValue)
        {
            throw new DomainException($"Each key needs a kid of 1 to {MaxKidLength} characters.");
        }

        if (!kids.Add(kidValue))
        {
            throw new DomainException("Each kid in the jwks must be unique.");
        }

        if (!key.TryGetProperty("kty", out var kty) || kty.ValueKind != JsonValueKind.String || kty.GetString() is not ("RSA" or "EC"))
        {
            throw new DomainException("Each key must have kty RSA or EC.");
        }

        // RFC 7517, section 4.2: a key for encryption cannot verify a client assertion.
        if (key.TryGetProperty("use", out var use) && (use.ValueKind != JsonValueKind.String || use.GetString() != "sig"))
        {
            throw new DomainException("A key with \"use\" must have the value \"sig\".");
        }
    }
}
