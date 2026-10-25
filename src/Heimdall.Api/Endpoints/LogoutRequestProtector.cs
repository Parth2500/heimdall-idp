using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Application.Logout;
using Microsoft.AspNetCore.DataProtection;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// Seals a checked logout target for the confirm page (U17). The page gets one opaque value and sends it back. It never
/// reads a return URL from its own address (U4), and a changed value fails to open.
/// </summary>
/// <remarks>
/// ASP.NET Core Data Protection encrypts and authenticates the value, and the time limit ends it after
/// <see cref="Lifetime"/>. Antiforgery uses the same key ring, so a scaled-out deployment already shares it. The value
/// names its tenant, so a value from one tenant opens on no other. After it opens, <see cref="LogoutService"/> checks the
/// client and the URI again.
/// </remarks>
internal sealed class LogoutRequestProtector
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    private readonly ITimeLimitedDataProtector _protector;

    public LogoutRequestProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("Heimdall.Logout.Request.v1").ToTimeLimitedDataProtector();
    }

    public string Protect(Guid tenantId, LogoutTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        var payload = JsonSerializer.Serialize(new Sealed(tenantId, target.ClientPk, target.PostLogoutRedirectUri, target.State), Json);
        return _protector.Protect(payload, Lifetime);
    }

    /// <summary>The target, or null when the value is malformed, changed, expired, or from another tenant.</summary>
    public LogoutTarget? Unprotect(Guid tenantId, string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 4096)
        {
            return null;
        }

        try
        {
            var sealedValue = JsonSerializer.Deserialize<Sealed>(_protector.Unprotect(value), Json);
            return sealedValue is not null && sealedValue.TenantId == tenantId && sealedValue.Uri is { Length: > 0 }
                ? new LogoutTarget(sealedValue.ClientPk, sealedValue.Uri, sealedValue.State)
                : null;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or FormatException)
        {
            return null;
        }
    }

    private sealed record Sealed(
        [property: JsonPropertyName("t")] Guid TenantId,
        [property: JsonPropertyName("c")] Guid ClientPk,
        [property: JsonPropertyName("u")] string Uri,
        [property: JsonPropertyName("s")] string? State);
}
