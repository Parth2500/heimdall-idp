using Heimdall.Domain.Common;

namespace Heimdall.Domain.Sessions;

/// <summary>
/// The public session ID, <c>sid</c> (D29): 128 random bits in base64url, always 22 characters. It names a session to a
/// client. It is not the cookie secret, and it cannot authenticate anything.
/// </summary>
public static class SessionSid
{
    public const int Length = 22;

    public static bool IsValid(string? value) =>
        value is { Length: Length } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>Returns the value, or throws when it is not a <c>sid</c>.</summary>
    public static string Require(string value, string name) =>
        IsValid(value) ? value : throw new DomainException($"{name} must be 22 base64url characters (128 bits).");
}
