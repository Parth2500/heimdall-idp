using Heimdall.Application.Common;

namespace Heimdall.UnitTests.Application;

public class ResultTests
{
    [Fact]
    public void Value_of_a_failure_throws()
    {
        var result = Result.Failure<string>(OAuthError.InvalidGrant("test"));

        var error = Assert.Throws<InvalidOperationException>(() => result.Value);
        Assert.Contains("invalid_grant", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Value_of_a_success_is_the_value()
    {
        var result = Result.Success("token");

        Assert.True(result.IsSuccess);
        Assert.Equal("token", result.Value);
    }
}
