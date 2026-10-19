using System.Net;
using System.Net.Sockets;

namespace Heimdall.Application.Common;

/// <summary>The key of a request source, for rate limits and the sign-in throttle.</summary>
public static class SourceKeys
{
    /// <summary>
    /// The IP address as text. An IPv6 address counts as its /64 network, because one host usually controls a whole /64
    /// and could otherwise rotate through it. An IPv4 address mapped into IPv6 counts as the IPv4 address.
    /// </summary>
    public static string For(IPAddress? address)
    {
        if (address is null)
        {
            return "unknown";
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            Array.Clear(bytes, 8, 8);
            return new IPAddress(bytes) + "/64";
        }

        return address.ToString();
    }
}
