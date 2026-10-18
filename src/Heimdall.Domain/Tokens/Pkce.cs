using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Heimdall.Domain.Tokens;

/// <summary>PKCE with the S256 method only (RFC 7636, D2). The method <c>plain</c> does not exist here.</summary>
public static class Pkce
{
    private const int MinVerifierLength = 43;
    private const int MaxVerifierLength = 128;

    // BASE64URL of a SHA-256 hash, without padding, is always 43 characters.
    private const int ChallengeLength = 43;

    /// <summary>A verifier has 43 to 128 characters from the unreserved set: A-Z a-z 0-9 - . _ ~</summary>
    public static bool IsValidVerifier(string? verifier)
    {
        if (verifier is null || verifier.Length < MinVerifierLength || verifier.Length > MaxVerifierLength)
        {
            return false;
        }

        foreach (var c in verifier)
        {
            var isUnreserved = char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';
            if (!isUnreserved)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>A challenge is the 43-character BASE64URL form of a SHA-256 hash.</summary>
    public static bool IsValidChallenge(string? challenge)
    {
        if (challenge is null || challenge.Length != ChallengeLength)
        {
            return false;
        }

        foreach (var c in challenge)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Checks that BASE64URL(SHA256(verifier)) equals the stored challenge, in fixed time.</summary>
    public static bool VerifyS256(string? verifier, string? challenge)
    {
        if (!IsValidVerifier(verifier) || !IsValidChallenge(challenge))
        {
            return false;
        }

        var computed = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier!)));
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computed),
            Encoding.ASCII.GetBytes(challenge!));
    }
}
