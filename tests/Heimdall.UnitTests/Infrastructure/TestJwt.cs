using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Heimdall.Application.Keys;

namespace Heimdall.UnitTests.Infrastructure;

/// <summary>Builds RS256 tokens for the validator tests, the way JwtTokenSigner does.</summary>
internal static class TestJwt
{
    public static RsaPublicJwk JwkOf(RSA rsa)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        return RsaPublicJwk.FromPublicParameters(
            Base64Url.EncodeToString(parameters.Modulus!),
            Base64Url.EncodeToString(parameters.Exponent!));
    }

    public static string Encode(JsonNode node) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(node.ToJsonString()));

    public static string SignSegments(string header, string payload, RSA key)
    {
        var input = header + "." + payload;
        var signature = key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return input + "." + Base64Url.EncodeToString(signature);
    }
}

/// <summary>Published keys for each tenant, in memory. It counts the reads.</summary>
internal sealed class FakeKeyCache : ISigningKeyCache
{
    public Dictionary<Guid, IReadOnlyList<RsaPublicJwk>> Keys { get; } = [];

    public int Reads { get; private set; }

    public ValueTask<ActiveSigningKey?> GetActiveKeyAsync(Guid tenantId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public ValueTask<IReadOnlyList<RsaPublicJwk>> GetPublishedKeysAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        Reads++;
        return ValueTask.FromResult(Keys.TryGetValue(tenantId, out var keys) ? keys : []);
    }

    public void Invalidate(Guid tenantId)
    {
    }
}
