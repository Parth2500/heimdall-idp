using System.Security.Cryptography;
using System.Text;

namespace Heimdall.Domain.Common;

/// <summary>
/// A SHA-256 hash of a code, refresh token, or client secret (D3). The type makes two rules hard to break:
/// the plain value is never stored, and two hashes are always compared in fixed time (D4).
/// </summary>
public readonly struct TokenHash : IEquatable<TokenHash>
{
    public const int Length = 32;

    private readonly byte[]? _bytes;

    private TokenHash(byte[] bytes) => _bytes = bytes;

    /// <summary>Hashes a high-entropy random value. Do not use it for user passwords (use Argon2id).</summary>
    public static TokenHash Compute(string secret)
    {
        Guard.NotBlank(secret, nameof(secret));
        return new TokenHash(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
    }

    /// <summary>Restores a hash that was read from the database.</summary>
    public static TokenHash FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new DomainException($"A token hash must be {Length} bytes long.");
        }

        return new TokenHash(bytes.ToArray());
    }

    public ReadOnlySpan<byte> AsSpan() => _bytes;

    public bool Equals(TokenHash other) =>
        _bytes is not null && other._bytes is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);

    public override bool Equals(object? obj) => obj is TokenHash other && Equals(other);

    public override int GetHashCode() => _bytes is null ? 0 : BitConverter.ToInt32(_bytes, 0);

    // Never print the value, so it cannot reach a log by accident (D7).
    public override string ToString() => "TokenHash(redacted)";

    public static bool operator ==(TokenHash left, TokenHash right) => left.Equals(right);

    public static bool operator !=(TokenHash left, TokenHash right) => !left.Equals(right);
}
