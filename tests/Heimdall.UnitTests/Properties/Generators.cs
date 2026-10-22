using CsCheck;

namespace Heimdall.UnitTests.Properties;

/// <summary>Input generators for the parser properties. Each one leans toward the characters that a parser treats specially.</summary>
internal static class Generators
{
    public const string Base64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>Any char, including control characters, unpaired surrogates, and non-ASCII letters.</summary>
    public static readonly Gen<char> AnyChar = Gen.Frequency(
        (4, Gen.Char[' ', '~']),
        (1, Gen.Char['\0', '\u001F']),
        (1, Gen.Char['\u007F', 'ÿ']),
        (1, Gen.Char['\uD800', '\uDFFF']),
        (1, Gen.Char['Ā', '￿']));

    public static readonly Gen<string> AnyString = Gen.String[AnyChar, 0, 80];

    /// <summary>Text that looks like a token: base64url runs, dots, and some stray characters.</summary>
    public static readonly Gen<string> TokenLike = Gen.String[
        Gen.Frequency((12, Gen.Char[Base64UrlChars]), (2, Gen.Const('.')), (1, Gen.Char["=+/ \t\n%"]), (1, AnyChar)),
        0,
        200];

    /// <summary>A character that RFC 6749, section 3.3 allows in a scope token.</summary>
    public static readonly Gen<char> ScopeChar = Gen.Char['!', '~'].Where(c => c is not '"' and not '\\');

    public static readonly Gen<string> ScopeToken = Gen.String[ScopeChar, 1, 12];

    /// <summary>
    /// Well-formed Unicode text: any scalar value, never an unpaired surrogate. UTF-8 can carry it without loss.
    /// </summary>
    public static readonly Gen<string> UnicodeText = Gen.Frequency(
            (6, Gen.Int[0x20, 0x7E]),
            (1, Gen.Int[0x00, 0x1F]),
            (2, Gen.Int[0xA0, 0xD7FF]),
            (1, Gen.Int[0xE000, 0xFFFD]),
            (1, Gen.Int[0x10000, 0x10FFFF]))
        .Array[0, 24]
        .Select(points => string.Concat(points.Select(char.ConvertFromUtf32)));
}
