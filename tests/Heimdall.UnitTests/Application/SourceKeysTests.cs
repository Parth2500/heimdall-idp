using System.Net;
using Heimdall.Application.Common;

namespace Heimdall.UnitTests.Application;

public class SourceKeysTests
{
    [Fact]
    public void Missing_address_is_unknown()
    {
        Assert.Equal("unknown", SourceKeys.For(null));
    }

    [Fact]
    public void IPv4_address_is_its_own_key()
    {
        Assert.Equal("203.0.113.7", SourceKeys.For(IPAddress.Parse("203.0.113.7")));
    }

    [Fact]
    public void IPv4_mapped_into_IPv6_counts_as_the_IPv4_address()
    {
        Assert.Equal("203.0.113.7", SourceKeys.For(IPAddress.Parse("::ffff:203.0.113.7")));
    }

    [Fact]
    public void IPv6_addresses_in_one_64_network_share_one_key()
    {
        var first = SourceKeys.For(IPAddress.Parse("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        var second = SourceKeys.For(IPAddress.Parse("2001:db8:1:2::1"));

        Assert.Equal("2001:db8:1:2::/64", first);
        Assert.Equal(first, second);
        Assert.NotEqual(first, SourceKeys.For(IPAddress.Parse("2001:db8:1:3::1")));
    }
}
