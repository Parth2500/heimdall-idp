using System.Globalization;

namespace Heimdall.Application.Users;

/// <summary>
/// D14 (NIST SP 800-63B): at least 12 and at most 128 characters, and no composition rules. Length counts
/// characters as a user sees them (text elements), so an emoji or an accented letter counts once.
/// </summary>
/// <remarks>The breached-password check of D14 is not built yet. It belongs with registration and password change.</remarks>
public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    /// <summary>The number of characters as a user sees them.</summary>
    public static int Length(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return new StringInfo(password).LengthInTextElements;
    }

    /// <summary>Null when the password is acceptable, or the reason when it is not.</summary>
    public static string? Check(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return "The password is empty.";
        }

        var length = Length(password);
        if (length < MinLength)
        {
            return $"The password must have at least {MinLength} characters.";
        }

        return length > MaxLength ? $"The password must have at most {MaxLength} characters." : null;
    }

    /// <summary>
    /// True when the input is too long to be any valid password. Login refuses it before hashing, so a huge input
    /// cannot make the server hash it. The UTF-16 length is a cheap upper bound: 4 code units for each character.
    /// </summary>
    public static bool IsTooLongToHash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return password.Length > MaxLength * 4 || Length(password) > MaxLength;
    }
}
