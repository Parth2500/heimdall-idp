using System.Globalization;

namespace Heimdall.Api.Hosting;

/// <summary>
/// Builds a tenant's issuer URL. The scheme is always https (D1). The host is the tenant's host (D21).
/// Nothing comes from the request, so a request cannot change the issuer.
/// </summary>
public sealed class IssuerOptions
{
    public const string SectionName = "Heimdall:Issuer";

    /// <summary>The public port, when it is not 443. Development uses the Kestrel port.</summary>
    public int? Port { get; set; }

    public string IssuerFor(string tenantHost)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantHost);
        return Port is null or 443
            ? $"https://{tenantHost}"
            : string.Create(CultureInfo.InvariantCulture, $"https://{tenantHost}:{Port}");
    }
}
