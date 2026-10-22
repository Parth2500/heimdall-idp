using System.Buffers.Text;
using System.Text.Json;
using System.Text.Unicode;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// Strict decoding of JWS parts (RFC 7515) for the validators of access tokens and DPoP proofs. Each method returns
/// null or false for bad input. None of them throws.
/// </summary>
internal static class Jws
{
    public static bool IsString(JsonElement element, string name, out string value)
    {
        // Stryker disable once String : the caller reads value only when this method returns true.
        value = string.Empty;
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString()!;
        return value.Length > 0;
    }

    public static JsonDocument? DecodeJson(string segment)
    {
        // JSON text is UTF-8 (RFC 8259, section 8.1). The parser checks the bytes of a string only when the string is
        // read, and then it throws. This check refuses the token instead, before any value is read.
        var bytes = Decode(segment);
        if (bytes is null || !Utf8.IsValid(bytes))
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        }
        // Stryker disable once Block : an empty catch also ends the method with null.
        catch (JsonException)
        {
            return null;
        }
    }

    // Base64url with no padding (RFC 7515, section 2), or null. Any other character fails.
    public static byte[]? Decode(string segment)
    {
        // The decoder skips white space, so each character is checked here instead.
        if (segment.Length == 0 || !segment.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
        {
            return null;
        }

        try
        {
            return Base64Url.DecodeFromChars(segment);
        }
        // Stryker disable once Block : an empty catch also ends the method with null.
        catch (FormatException)
        {
            return null;
        }
    }
}
