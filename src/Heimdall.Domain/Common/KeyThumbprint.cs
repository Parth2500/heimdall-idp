namespace Heimdall.Domain.Common;

/// <summary>An RFC 7638 SHA-256 key thumbprint in base64url: always 43 characters (D24).</summary>
public static class KeyThumbprint
{
    public const int Length = 43;

    public static bool IsValid(string? value) =>
        value is { Length: Length } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>Returns the value, or throws when it is not a thumbprint.</summary>
    public static string Require(string value, string name) =>
        IsValid(value) ? value : throw new DomainException($"{name} must be an RFC 7638 SHA-256 thumbprint in base64url.");
}
