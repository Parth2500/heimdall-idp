using System.Net;
using Heimdall.Infrastructure.Logout;

namespace Heimdall.UnitTests.Infrastructure;

/// <summary>D35: a back-channel call never reaches an internal address outside Development (server-side request forgery).</summary>
public class OutboundAddressGuardTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.255.255.254")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")] // Cloud metadata.
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.255")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("fe80::1")]
    [InlineData("ff02::1")]
    [InlineData("64:ff9b::a00:1")] // NAT64 of 10.0.0.1.
    [InlineData("::ffff:127.0.0.1")] // IPv4-mapped forms of blocked IPv4 addresses.
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("::10.0.0.1")] // IPv4-compatible.
    [InlineData("::127.0.0.1")]
    [InlineData("2002:a00:1::1")] // 6to4 of 10.0.0.1.
    [InlineData("2002:5db8:d822::1")] // 6to4 of a public address: blocked too, the whole range is.
    [InlineData("2001:0:4136:e378::1")] // Teredo.
    [InlineData("2001:db8::1")]
    [InlineData("100::1")]
    [InlineData("64:ff9b:1::a00:1")] // Local-use NAT64 (RFC 8215).
    [InlineData("::ffff:0:a00:1")] // IPv4-translated (SIIT) form of 10.0.0.1.
    [InlineData("2001:2::1")] // Benchmarking.
    [InlineData("2001:10::1")] // ORCHID.
    [InlineData("3fff::1")]
    [InlineData("4000::1")] // Outside global unicast.
    [InlineData("192.0.0.8")]
    [InlineData("192.0.2.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.19.255.255")]
    [InlineData("198.51.100.7")]
    [InlineData("203.0.113.7")]
    public void Internal_address_is_blocked(string address) =>
        Assert.False(OutboundAddressGuard.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("93.184.216.34")]
    [InlineData("8.8.8.8")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.0")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.0")]
    [InlineData("169.253.255.255")]
    [InlineData("11.0.0.0")]
    [InlineData("223.255.255.255")]
    [InlineData("2606:4700::1111")]
    [InlineData("2001:4860::8888")] // Outside the IETF block (2001::/23).
    [InlineData("2a00:1450::1")]
    [InlineData("2003::1")]
    [InlineData("198.17.255.255")]
    [InlineData("198.20.0.0")]
    [InlineData("::ffff:93.184.216.34")]
    public void Public_address_is_allowed(string address) =>
        Assert.True(OutboundAddressGuard.IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("http://127.0.0.1:9/backchannel")]
    [InlineData("http://[::1]:9/backchannel")]
    [InlineData("http://localhost:9/backchannel")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    public async Task Connection_to_an_internal_host_is_refused_before_a_socket_opens(string uri)
    {
        using var handler = new SocketsHttpHandler { ConnectCallback = OutboundAddressGuard.ConnectAsync };
        using var client = new HttpClient(handler);

        var error = await Assert.ThrowsAsync<HttpRequestException>(() => client.PostAsync(uri, new StringContent("x")));

        Assert.Contains("blocked address", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Host_with_only_public_addresses_is_kept_unchanged()
    {
        IPAddress[] addresses = [IPAddress.Parse("93.184.216.34"), IPAddress.Parse("2606:4700::1111")];

        Assert.Same(addresses, OutboundAddressGuard.Checked("app.example.com", addresses));
    }

    [Fact]
    public void One_blocked_address_refuses_the_whole_host()
    {
        // DNS rebinding: a name that also resolves to the metadata address is not trusted at all.
        IPAddress[] addresses = [IPAddress.Parse("93.184.216.34"), IPAddress.Parse("169.254.169.254")];

        var error = Assert.Throws<HttpRequestException>(() => OutboundAddressGuard.Checked("app.example.com", addresses));
        Assert.Contains("'app.example.com'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Blocked_address_first_refuses_the_host_too() =>
        Assert.Throws<HttpRequestException>(() => OutboundAddressGuard.Checked("h", [IPAddress.Parse("10.0.0.1"), IPAddress.Parse("93.184.216.34")]));

    [Fact]
    public void Host_with_no_address_is_refused() =>
        Assert.Throws<HttpRequestException>(() => OutboundAddressGuard.Checked("h", []));
}
