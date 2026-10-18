namespace Heimdall.Application.Users;

/// <param name="Verified">True when the password matches the hash.</param>
/// <param name="NeedsRehash">True when the hash uses older parameters than the current settings.</param>
public readonly record struct PasswordCheck(bool Verified, bool NeedsRehash);

/// <summary>
/// Argon2id for user passwords only (D3). Hashing is slow on purpose. The implementation limits how many hashes run
/// at the same time, so a flood of login requests cannot use all CPU and memory (threat model, login, Denial of service).
/// </summary>
public interface IPasswordHasher
{
    /// <summary>Returns an encoded Argon2id hash. The string holds the salt and the parameters.</summary>
    /// <exception cref="PasswordHasherBusyException">Too many hashes are waiting.</exception>
    ValueTask<string> HashAsync(string password, CancellationToken cancellationToken);

    /// <summary>
    /// Checks a password. When <paramref name="hash"/> is null (an unknown user), the hasher does the same work
    /// against a dummy hash and returns not verified, so the response time does not show whether the account exists.
    /// </summary>
    /// <exception cref="PasswordHasherBusyException">Too many hashes are waiting.</exception>
    ValueTask<PasswordCheck> VerifyAsync(string? hash, string password, CancellationToken cancellationToken);
}

/// <summary>Too many password hashes are waiting. The caller should answer "try again later", not "wrong password".</summary>
public sealed class PasswordHasherBusyException : Exception
{
    public PasswordHasherBusyException()
        : base("Too many password hashes are waiting.")
    {
    }

    public PasswordHasherBusyException(string message)
        : base(message)
    {
    }

    public PasswordHasherBusyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
