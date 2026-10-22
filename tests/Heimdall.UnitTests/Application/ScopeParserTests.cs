using Heimdall.Application.Common;

namespace Heimdall.UnitTests.Application;

public class ScopeParserTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void No_scope_is_an_empty_list(string? scope)
    {
        Assert.Empty(ScopeParser.Parse(scope)!);
    }

    [Fact]
    public void Values_are_split_on_spaces_and_duplicates_are_removed()
    {
        Assert.Equal(["read", "write"], ScopeParser.Parse("  read write  read ")!);
    }

    [Fact]
    public void Duplicates_are_case_sensitive()
    {
        Assert.Equal(["read", "READ"], ScopeParser.Parse("read READ")!);
    }

    [Theory]
    [InlineData("!")] // 0x21, the first allowed character
    [InlineData("~")] // 0x7E, the last allowed character
    [InlineData("#")] // 0x23, between the two excluded characters and the first one
    [InlineData("[]")] // 0x5B and 0x5D, next to the backslash
    [InlineData("invoices:read/all")]
    public void Characters_of_the_scope_token_set_are_accepted(string scope)
    {
        Assert.Equal([scope], ScopeParser.Parse(scope)!);
    }

    [Theory]
    [InlineData("read\"")] // 0x22
    [InlineData("read\\")] // 0x5C
    [InlineData("read\u007F")] // DEL, one above the set
    [InlineData("read\u001F")] // a control character below the space
    [InlineData("read\t")]
    [InlineData("lés")] // outside ASCII
    public void A_character_outside_the_scope_token_set_rejects_the_whole_parameter(string bad)
    {
        Assert.Null(ScopeParser.Parse("openid " + bad));
    }
}
