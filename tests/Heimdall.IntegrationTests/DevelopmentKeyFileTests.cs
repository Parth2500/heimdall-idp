using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Heimdall.Infrastructure.Keys;

namespace Heimdall.IntegrationTests;

/// <summary>The development key file needs no database, so these tests always run.</summary>
public sealed class DevelopmentKeyFileTests : IDisposable
{
    private static readonly byte[] Data = Encoding.ASCII.GetBytes("header.payload");

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "heimdall-tests", Guid.NewGuid().ToString("N"));

    private string KeyFilePath => Path.Combine(_directory, ".local", "signing-keys.json");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static bool Verify(string n, string e, byte[] signature)
    {
        using var rsa = RSA.Create(new RSAParameters { Modulus = Base64Url.DecodeFromChars(n), Exponent = Base64Url.DecodeFromChars(e) });
        return rsa.VerifyData(Data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    [Fact]
    public async Task Created_key_signs_and_the_public_parameters_verify_it()
    {
        using var store = new DevelopmentKeyFile(KeyFilePath);

        var created = await store.CreateRsaKeyAsync(CancellationToken.None);
        var signature = await store.SignRs256Async(created.PrivateKeyRef, Data, CancellationToken.None);

        Assert.StartsWith(DevelopmentKeyFile.ReferencePrefix, created.PrivateKeyRef, StringComparison.Ordinal);
        Assert.Equal(2048, Base64Url.DecodeFromChars(created.N).Length * 8);
        Assert.True(Verify(created.N, created.E, signature));
    }

    [Fact]
    public async Task Missing_file_and_folder_are_created()
    {
        using var store = new DevelopmentKeyFile(KeyFilePath);

        await store.CreateRsaKeyAsync(CancellationToken.None);

        Assert.True(File.Exists(KeyFilePath));
    }

    [Fact]
    public async Task Another_instance_reads_a_key_from_the_file()
    {
        // For example, seed-dev creates the key while the server already runs.
        using var writer = new DevelopmentKeyFile(KeyFilePath);
        using var reader = new DevelopmentKeyFile(KeyFilePath);
        _ = await reader.CreateRsaKeyAsync(CancellationToken.None);

        var created = await writer.CreateRsaKeyAsync(CancellationToken.None);
        var signature = await reader.SignRs256Async(created.PrivateKeyRef, Data, CancellationToken.None);

        Assert.True(Verify(created.N, created.E, signature));
    }

    [Fact]
    public async Task Second_key_does_not_remove_the_first()
    {
        using var store = new DevelopmentKeyFile(KeyFilePath);
        var first = await store.CreateRsaKeyAsync(CancellationToken.None);
        await store.CreateRsaKeyAsync(CancellationToken.None);

        using var fresh = new DevelopmentKeyFile(KeyFilePath);
        var signature = await fresh.SignRs256Async(first.PrivateKeyRef, Data, CancellationToken.None);

        Assert.True(Verify(first.N, first.E, signature));
    }

    [Fact]
    public async Task File_is_readable_by_the_owner_only()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var store = new DevelopmentKeyFile(KeyFilePath);
        await store.CreateRsaKeyAsync(CancellationToken.None);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(KeyFilePath));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(Path.GetDirectoryName(KeyFilePath)!));
    }

    [Fact]
    public async Task Reference_of_another_store_is_rejected()
    {
        using var store = new DevelopmentKeyFile(KeyFilePath);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.SignRs256Async("https://vault.example.net/keys/k1/v1", Data, CancellationToken.None));
    }

    [Fact]
    public async Task Unknown_reference_is_rejected()
    {
        using var store = new DevelopmentKeyFile(KeyFilePath);
        await store.CreateRsaKeyAsync(CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.SignRs256Async(DevelopmentKeyFile.ReferencePrefix + "missing", Data, CancellationToken.None));
    }
}
