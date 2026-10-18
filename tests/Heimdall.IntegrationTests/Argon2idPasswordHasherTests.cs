using Heimdall.Application.Users;
using Heimdall.Infrastructure.Users;

namespace Heimdall.IntegrationTests;

/// <summary>The real libsodium Argon2id. It needs no database, so these tests always run.</summary>
public sealed class Argon2idPasswordHasherTests : IDisposable
{
    private const string Password = "correct horse battery staple";

    // The smallest allowed parameters keep the tests fast.
    private static readonly PasswordHashingOptions Fast = new() { MemoryKiB = 19 * 1024, Iterations = 3 };

    private readonly Argon2idPasswordHasher _hasher = new(Fast);

    public void Dispose() => _hasher.Dispose();

    [Fact]
    public async Task Hash_is_an_encoded_Argon2id_string_with_its_parameters_and_a_salt()
    {
        var first = await _hasher.HashAsync(Password, CancellationToken.None);
        var second = await _hasher.HashAsync(Password, CancellationToken.None);

        Assert.StartsWith("$argon2id$v=19$m=19456,t=3,p=1$", first, StringComparison.Ordinal);
        Assert.NotEqual(first, second); // A random salt for each hash.
        Assert.DoesNotContain(Password, first, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verify_accepts_the_password_and_refuses_others()
    {
        var hash = await _hasher.HashAsync(Password, CancellationToken.None);

        Assert.Equal(new PasswordCheck(true, false), await _hasher.VerifyAsync(hash, Password, CancellationToken.None));
        Assert.False((await _hasher.VerifyAsync(hash, Password + " ", CancellationToken.None)).Verified);
        Assert.False((await _hasher.VerifyAsync(hash, "Correct horse battery staple", CancellationToken.None)).Verified);
    }

    [Fact]
    public async Task Unknown_user_verifies_against_a_dummy_and_fails()
    {
        Assert.Equal(new PasswordCheck(false, false), await _hasher.VerifyAsync(null, Password, CancellationToken.None));
    }

    [Fact]
    public async Task Malformed_hash_fails_without_an_exception()
    {
        Assert.False((await _hasher.VerifyAsync("$argon2id$garbage", Password, CancellationToken.None)).Verified);
    }

    [Fact]
    public async Task Unicode_forms_of_one_password_match()
    {
        // NFKC: the "ﬁ" ligature and full-width letters become plain "fi" and "AB".
        var hash = await _hasher.HashAsync("ﬁne password ＡＢ", CancellationToken.None);

        Assert.True((await _hasher.VerifyAsync(hash, "fine password AB", CancellationToken.None)).Verified);
    }

    [Fact]
    public async Task Hash_with_weaker_parameters_needs_a_rehash()
    {
        var weakHash = await _hasher.HashAsync(Password, CancellationToken.None);
        using var stronger = new Argon2idPasswordHasher(new PasswordHashingOptions { MemoryKiB = 32 * 1024, Iterations = 3 });

        var check = await stronger.VerifyAsync(weakHash, Password, CancellationToken.None);

        Assert.Equal(new PasswordCheck(true, true), check);
        var upgraded = await stronger.HashAsync(Password, CancellationToken.None);
        Assert.StartsWith("$argon2id$v=19$m=32768,t=3,p=1$", upgraded, StringComparison.Ordinal);
        Assert.False((await stronger.VerifyAsync(upgraded, Password, CancellationToken.None)).NeedsRehash);
    }

    [Fact]
    public async Task Full_gate_fails_fast_instead_of_queueing()
    {
        // One slot and no queue. A slow hash holds the slot while the second request arrives.
        using var gated = new Argon2idPasswordHasher(new PasswordHashingOptions
        {
            MemoryKiB = 256 * 1024,
            Iterations = 8,
            MaxConcurrentHashes = 1,
            MaxQueueWait = TimeSpan.Zero,
        });

        var slow = Task.Run(() => gated.HashAsync(Password, CancellationToken.None).AsTask());
        Assert.True(SpinWait.SpinUntil(() => gated.AvailableSlots == 0, TimeSpan.FromSeconds(10)));

        await Assert.ThrowsAsync<PasswordHasherBusyException>(() => gated.VerifyAsync(null, Password, CancellationToken.None).AsTask());
        await slow;
        Assert.Equal(1, gated.AvailableSlots);
    }
}
