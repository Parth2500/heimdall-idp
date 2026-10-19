using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Heimdall.Api.Hosting;

/// <summary>
/// The reverse proxies that Heimdall trusts for <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c>. With none
/// configured, Heimdall reads no forwarded header: the connection itself is the client.
/// </summary>
public sealed class ProxyOptions
{
    public const string SectionName = "Heimdall:ForwardedHeaders";

    /// <summary>Proxy addresses, for example <c>10.0.0.5</c>.</summary>
    public IList<string> KnownProxies { get; } = [];

    /// <summary>Proxy networks in CIDR form, for example <c>10.0.0.0/24</c>.</summary>
    public IList<string> KnownNetworks { get; } = [];

    public bool IsEnabled => KnownProxies.Count > 0 || KnownNetworks.Count > 0;

    /// <summary>Checks the values. Call it at startup, so a bad configuration stops the server.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        errors.AddRange(KnownProxies.Where(p => !IPAddress.TryParse(p, out _)).Select(p => $"{nameof(KnownProxies)}: '{p}' is not an IP address."));
        errors.AddRange(KnownNetworks.Where(n => !System.Net.IPNetwork.TryParse(n, out _)).Select(n => $"{nameof(KnownNetworks)}: '{n}' is not a CIDR network."));
        return errors;
    }

    /// <summary>
    /// The middleware options. <c>X-Forwarded-Host</c> is never read: the host chooses the tenant and the issuer (D21),
    /// so the proxy must pass the original Host header. One hop only: a client can add addresses to the left of
    /// <c>X-Forwarded-For</c>, but the trusted proxy appends the real one on the right.
    /// </summary>
    public ForwardedHeadersOptions ToMiddlewareOptions()
    {
        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 1,

            // Off: a proxy appends to a client's own X-Forwarded-For but sends one X-Forwarded-Proto. With symmetry
            // required, any client header would make the middleware ignore both, and the request would fail. One hop
            // reads only the rightmost value of each, which the proxy wrote.
            RequireHeaderSymmetry = false,
        };

        // The defaults trust loopback. Heimdall trusts only what the operator configured.
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var proxy in KnownProxies)
        {
            options.KnownProxies.Add(IPAddress.Parse(proxy));
        }

        foreach (var network in KnownNetworks)
        {
            options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
        }

        return options;
    }
}
