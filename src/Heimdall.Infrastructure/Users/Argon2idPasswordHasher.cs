using System.Security.Cryptography;
using System.Text;
using Heimdall.Application.Users;
using Sodium;

namespace Heimdall.Infrastructure.Users;

/// <summary>
/// Argon2id through libsodium (<c>crypto_pwhash_str</c>). The encoded string holds the algorithm, the parameters, and
/// a random salt, for example <c>$argon2id$v=19$m=65536,t=3,p=1$...</c>. libsodium compares in constant time.
/// </summary>
/// <remarks>
/// A gate allows <see cref="PasswordHashingOptions.MaxConcurrentHashes"/> hashes at the same time. Each hash holds
/// <see cref="PasswordHashingOptions.MemoryKiB"/> of memory, so the gate also caps the memory that logins can use.
/// A request that cannot get a slot within <see cref="PasswordHashingOptions.MaxQueueWait"/> fails fast.
/// </remarks>
internal sealed class Argon2idPasswordHasher : IPasswordHasher, IDisposable
{
    private readonly long _opsLimit;
    private readonly int _memLimitBytes;
    private readonly TimeSpan _maxQueueWait;
    private readonly SemaphoreSlim _gate;
    private readonly Lazy<string> _dummyHash;

    public Argon2idPasswordHasher(PasswordHashingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _opsLimit = options.Iterations;
        _memLimitBytes = checked(options.MemoryKiB * 1024);
        _maxQueueWait = options.MaxQueueWait;
        _gate = new SemaphoreSlim(options.MaxConcurrentHashes, options.MaxConcurrentHashes);

        // The dummy uses the current parameters, so verifying against it costs the same as against a real hash.
        _dummyHash = new Lazy<string>(() => Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))));
    }

    public async ValueTask<string> HashAsync(string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return Hash(password);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<PasswordCheck> VerifyAsync(string? hash, string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);
        await EnterAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (hash is null)
            {
                _ = PasswordHash.ArgonHashStringVerify(_dummyHash.Value, Normalize(password));
                return new PasswordCheck(false, false);
            }

            var verified = PasswordHash.ArgonHashStringVerify(hash, Normalize(password));
            var needsRehash = verified && PasswordHash.ArgonPasswordNeedsRehash(Encoding.ASCII.GetBytes(hash), _opsLimit, _memLimitBytes);
            return new PasswordCheck(verified, needsRehash);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Free hash slots now. For tests.</summary>
    internal int AvailableSlots => _gate.CurrentCount;

    public void Dispose() => _gate.Dispose();

    private string Hash(string password) => PasswordHash.ArgonHashString(Normalize(password), _opsLimit, _memLimitBytes);

    // NIST SP 800-63B: normalize Unicode (NFKC) before hashing, so the same password typed on different keyboards or
    // input methods gives the same bytes.
    private static string Normalize(string password) => password.Normalize(NormalizationForm.FormKC);

    private async Task EnterAsync(CancellationToken cancellationToken)
    {
        if (!await _gate.WaitAsync(_maxQueueWait, cancellationToken).ConfigureAwait(false))
        {
            throw new PasswordHasherBusyException();
        }
    }
}
