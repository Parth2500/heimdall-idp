namespace Heimdall.Application.Users;

/// <summary>Argon2id parameters and the concurrency limit. The values come from configuration.</summary>
public sealed class PasswordHashingOptions
{
    public const string SectionName = "Heimdall:PasswordHashing";

    // OWASP Password Storage Cheat Sheet: the smallest Argon2id setting it lists is 19 MiB with 2 passes.
    // The libsodium wrapper (Sodium.Core) requires at least 3 passes, so the floor here is 3.
    private const int MinMemoryKiB = 19 * 1024;
    private const int MinIterations = 3;

    /// <summary>Memory for one hash, in KiB. 64 MiB by default.</summary>
    public int MemoryKiB { get; set; } = 64 * 1024;

    /// <summary>Passes over the memory (Argon2 t).</summary>
    public int Iterations { get; set; } = 3;

    /// <summary>Hashes that run at the same time. Each one holds <see cref="MemoryKiB"/> of memory.</summary>
    public int MaxConcurrentHashes { get; set; } = Environment.ProcessorCount;

    /// <summary>How long a request waits for a free slot before it fails with "try again later".</summary>
    public TimeSpan MaxQueueWait { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Checks the values. Call it at startup, so a bad configuration stops the server.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (MemoryKiB < MinMemoryKiB)
        {
            errors.Add($"{nameof(MemoryKiB)}: the value must be at least {MinMemoryKiB} (19 MiB).");
        }

        if (Iterations < MinIterations)
        {
            errors.Add($"{nameof(Iterations)}: the value must be at least {MinIterations}.");
        }

        if (MaxConcurrentHashes < 1)
        {
            errors.Add($"{nameof(MaxConcurrentHashes)}: the value must be at least 1.");
        }

        if (MaxQueueWait < TimeSpan.Zero)
        {
            errors.Add($"{nameof(MaxQueueWait)}: the value must not be negative.");
        }

        return errors;
    }
}
