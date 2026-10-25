using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace Heimdall.Infrastructure.Logout;

/// <summary>
/// Refuses a connection from Heimdall's server to an internal address (D35): server-side request forgery. The check
/// runs on the resolved address at connect time, and the socket connects to the checked address, so a DNS change after
/// registration (DNS rebinding) cannot reach an internal service.
/// </summary>
public static class OutboundAddressGuard
{
    // D35. Each IPv4 range also applies to its IPv4-mapped IPv6 form (::ffff:a.b.c.d).
    private static readonly (IPAddress Network, int PrefixLength)[] BlockedV4 =
    [
        (IPAddress.Parse("0.0.0.0"), 8),
        (IPAddress.Parse("10.0.0.0"), 8),
        (IPAddress.Parse("100.64.0.0"), 10),
        (IPAddress.Parse("127.0.0.0"), 8),
        (IPAddress.Parse("169.254.0.0"), 16), // Link-local, with the cloud metadata address 169.254.169.254.
        (IPAddress.Parse("172.16.0.0"), 12),
        (IPAddress.Parse("192.0.0.0"), 24), // IETF protocol assignments.
        (IPAddress.Parse("192.0.2.0"), 24), // Documentation (TEST-NET-1).
        (IPAddress.Parse("192.168.0.0"), 16),
        (IPAddress.Parse("198.18.0.0"), 15), // Benchmarking.
        (IPAddress.Parse("198.51.100.0"), 24), // Documentation (TEST-NET-2).
        (IPAddress.Parse("203.0.113.0"), 24), // Documentation (TEST-NET-3).
        (IPAddress.Parse("224.0.0.0"), 4), // Multicast.
        (IPAddress.Parse("240.0.0.0"), 4), // Reserved, with the broadcast address.
    ];

    // IPv6 is an allow-list: only global unicast (2000::/3, RFC 4291) counts. Every other range is out by default:
    // ::/96, IPv4-translated ::ffff:0:0:0/96, NAT64 (64:ff9b::/96 and 64:ff9b:1::/48), 100::/64, fc00::/7, fe80::/10,
    // and ff00::/8. A relay or a gateway could turn an IPv4-carrying form into an internal IPv4 address.
    private static readonly IPNetwork GlobalUnicastV6 = new(IPAddress.Parse("2000::"), 3);

    // The special ranges inside 2000::/3 (IANA IPv6 special-purpose registry).
    private static readonly (IPAddress Network, int PrefixLength)[] BlockedV6 =
    [
        (IPAddress.Parse("2001::"), 23), // IETF protocol assignments, with Teredo, benchmarking, and ORCHID.
        (IPAddress.Parse("2001:db8::"), 32), // Documentation.
        (IPAddress.Parse("2002::"), 16), // 6to4, deprecated by RFC 7526.
        (IPAddress.Parse("3fff::"), 20), // Documentation (RFC 9637).
    ];

    /// <summary>True when Heimdall may connect to the address outside Development.</summary>
    public static bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !BlockedV4.Any(range => new IPNetwork(range.Network, range.PrefixLength).Contains(address));
        }

        return address.AddressFamily == AddressFamily.InterNetworkV6
            && GlobalUnicastV6.Contains(address)
            && !BlockedV6.Any(range => new IPNetwork(range.Network, range.PrefixLength).Contains(address));
    }

    /// <summary>
    /// A <see cref="SocketsHttpHandler.ConnectCallback"/> that resolves the host, refuses it when any of its addresses is
    /// blocked, and connects to the checked addresses only.
    /// </summary>
    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var endPoint = context.DnsEndPoint;
        var addresses = IPAddress.TryParse(endPoint.Host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(endPoint.Host, cancellationToken).ConfigureAwait(false);

        // One blocked address refuses the host. A name that resolves to a public and a private address is not trusted.
        if (addresses.Length == 0 || !addresses.All(IsAllowed))
        {
            throw new HttpRequestException($"Heimdall refuses to connect to '{endPoint.Host}': it resolves to a blocked address (D35).");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, endPoint.Port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
