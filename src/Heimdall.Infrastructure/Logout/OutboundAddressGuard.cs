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

    // The IPv6 forms that can carry an IPv4 address are blocked whole: IPv4-compatible (::/96), 6to4 (2002::/16,
    // deprecated by RFC 7526), Teredo (2001::/32), and NAT64. A relay or a gateway could turn them into an internal IPv4
    // address, and no public client endpoint needs them.
    private static readonly (IPAddress Network, int PrefixLength)[] BlockedV6 =
    [
        (IPAddress.IPv6None, 96), // ::/96: the unspecified address, ::1, and the IPv4-compatible form.
        (IPAddress.Parse("100::"), 64), // Discard only.
        (IPAddress.Parse("2001::"), 32), // Teredo.
        (IPAddress.Parse("2001:db8::"), 32), // Documentation.
        (IPAddress.Parse("2002::"), 16), // 6to4.
        (IPAddress.Parse("fc00::"), 7),
        (IPAddress.Parse("fe80::"), 10),
        (IPAddress.Parse("ff00::"), 8), // Multicast.
        (IPAddress.Parse("64:ff9b::"), 96), // NAT64: a gateway would turn it into any IPv4 address, internal ones too.
    ];

    /// <summary>True when Heimdall may connect to the address outside Development.</summary>
    public static bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var blocked = address.AddressFamily == AddressFamily.InterNetwork ? BlockedV4 : BlockedV6;
        return !blocked.Any(range => new IPNetwork(range.Network, range.PrefixLength).Contains(address));
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
