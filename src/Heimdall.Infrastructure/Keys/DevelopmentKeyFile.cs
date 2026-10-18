using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Heimdall.Application.Keys;

namespace Heimdall.Infrastructure.Keys;

/// <summary>
/// The key store for local development: a JSON file in <c>.local/</c>, which git ignores
/// (docs/schema-design.md, "Local development signing keys"). The Api registers it only in the Development
/// environment. The keys are not trusted outside the local machine.
/// </summary>
/// <remarks>
/// The file holds plain PKCS#8 keys. Its protection is the file mode (owner only, on Unix) and the rule that the
/// file never leaves the machine. Two processes that create a key at the same moment can lose one write. This is
/// accepted for a development store.
/// </remarks>
public sealed class DevelopmentKeyFile : IKeyMaterialStore, IDisposable
{
    /// <summary>The scheme of every reference this store creates. Another store rejects it.</summary>
    public const string ReferencePrefix = "devfile:";

    // 2048 bits is the RS256 size that every JOSE library and cloud KMS supports. NIST SP 800-57 allows it
    // through 2030. Keys rotate, so a later key can be larger with no change to this code.
    private const int KeySizeInBits = 2048;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _path;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly ConcurrentDictionary<string, byte[]> _keys = new(StringComparer.Ordinal);

    public DevelopmentKeyFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public string FilePath => _path;

    public void Dispose() => _fileLock.Dispose();

    public async Task<CreatedKeyMaterial> CreateRsaKeyAsync(CancellationToken cancellationToken)
    {
        using var rsa = RSA.Create(KeySizeInBits);
        var reference = ReferencePrefix + Guid.CreateVersion7().ToString("N");
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        var publicParameters = rsa.ExportParameters(includePrivateParameters: false);

        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var content = await ReadFileAsync(cancellationToken).ConfigureAwait(false);
            content.Keys[reference] = Convert.ToBase64String(pkcs8);
            await WriteFileAsync(content, cancellationToken).ConfigureAwait(false);
            _keys[reference] = pkcs8;
        }
        finally
        {
            _fileLock.Release();
        }

        return new CreatedKeyMaterial(
            reference,
            Base64Url.EncodeToString(publicParameters.Modulus),
            Base64Url.EncodeToString(publicParameters.Exponent));
    }

    public async Task<byte[]> SignRs256Async(string privateKeyRef, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyRef);

        if (!privateKeyRef.StartsWith(ReferencePrefix, StringComparison.Ordinal))
        {
            // A Key Vault or KMS reference must never fall back to a file key.
            throw new InvalidOperationException("The private key reference does not belong to the development key file.");
        }

        var pkcs8 = await GetKeyAsync(privateKeyRef, cancellationToken).ConfigureAwait(false);

        // A new RSA object for each call: RSA instances are not documented as safe for concurrent use.
        // This is a development store, so the import cost does not matter.
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8, out _);
        return rsa.SignData(data.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private async Task<byte[]> GetKeyAsync(string reference, CancellationToken cancellationToken)
    {
        if (_keys.TryGetValue(reference, out var cached))
        {
            return cached;
        }

        // Another process (for example seed-dev) can add a key after this process loaded the file.
        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var content = await ReadFileAsync(cancellationToken).ConfigureAwait(false);
            if (!content.Keys.TryGetValue(reference, out var encoded))
            {
                throw new InvalidOperationException(
                    $"The development key file '{_path}' has no key for a signing key in the database. " +
                    "The file and the database are out of step. Reset the development database and run seed-dev again.");
            }

            var pkcs8 = Convert.FromBase64String(encoded);
            _keys[reference] = pkcs8;
            return pkcs8;
        }
        finally
        {
            _fileLock.Release();
        }
    }

    private async Task<KeyFileContent> ReadFileAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new KeyFileContent();
        }

        var stream = File.OpenRead(_path);
        await using (stream.ConfigureAwait(false))
        {
            return await JsonSerializer.DeserializeAsync<KeyFileContent>(stream, JsonOptions, cancellationToken).ConfigureAwait(false)
                ?? new KeyFileContent();
        }
    }

    private async Task WriteFileAsync(KeyFileContent content, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)!;
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        // Write a new file and rename it over the old one, so a crash never leaves a half-written key file.
        var temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            // Owner read and write only. The mode is set at creation, so no other user can open the file first.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        var stream = new FileStream(temporaryPath, options);
        await using (stream.ConfigureAwait(false))
        {
            await JsonSerializer.SerializeAsync(stream, content, JsonOptions, cancellationToken).ConfigureAwait(false);
        }

        File.Move(temporaryPath, _path, overwrite: true);
    }

    private sealed class KeyFileContent
    {
        public string Warning { get; set; } =
            "Development signing keys. Do not copy this file to another machine or use these keys outside development.";

        /// <summary>Private key reference to the base64 PKCS#8 private key.</summary>
        public Dictionary<string, string> Keys { get; set; } = new(StringComparer.Ordinal);
    }
}
