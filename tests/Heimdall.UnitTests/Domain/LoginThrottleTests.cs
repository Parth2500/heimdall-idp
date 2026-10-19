using Heimdall.Domain.Common;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Domain;

public class LoginThrottleTests
{
    private static readonly TimeSpan Max = TimeSpan.FromMinutes(15);

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void Free_failures_have_no_wait(int failures)
    {
        Assert.Null(LoginThrottle.DelayAfter(failures, 5, Max));
    }

    [Theory]
    [InlineData(6, 1)]
    [InlineData(7, 2)]
    [InlineData(8, 4)]
    [InlineData(14, 256)]
    public void The_wait_doubles_after_the_free_failures(int failures, int seconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(seconds), LoginThrottle.DelayAfter(failures, 5, Max));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(1_000)]
    [InlineData(int.MaxValue)]
    public void The_wait_never_passes_the_maximum(int failures)
    {
        Assert.Equal(Max, LoginThrottle.DelayAfter(failures, 5, Max));
    }

    [Fact]
    public void Bad_settings_are_refused()
    {
        Assert.Throws<DomainException>(() => LoginThrottle.DelayAfter(6, -1, Max));
        Assert.ThrowsAny<Exception>(() => LoginThrottle.DelayAfter(6, 5, TimeSpan.Zero));
    }
}
