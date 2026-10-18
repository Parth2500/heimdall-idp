using Heimdall.Application.Users;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Application;

public class PasswordPolicyTests
{
    [Theory]
    [InlineData("12345678901", false)]
    [InlineData("123456789012", true)]
    [InlineData("only lowercase words here", true)] // D14: no composition rules.
    public void Length_rule_is_twelve_or_more(string password, bool accepted)
    {
        Assert.Equal(accepted, PasswordPolicy.Check(password) is null);
    }

    [Fact]
    public void Length_counts_characters_as_a_user_sees_them()
    {
        // Twelve emoji: 24 UTF-16 code units, but twelve characters.
        var emoji = string.Concat(Enumerable.Repeat("\U0001F600", 12));

        Assert.Equal(12, PasswordPolicy.Length(emoji));
        Assert.Null(PasswordPolicy.Check(emoji));
    }

    [Fact]
    public void More_than_128_characters_is_refused()
    {
        Assert.Null(PasswordPolicy.Check(new string('a', 128)));
        Assert.NotNull(PasswordPolicy.Check(new string('a', 129)));
        Assert.True(PasswordPolicy.IsTooLongToHash(new string('a', 129)));
        Assert.False(PasswordPolicy.IsTooLongToHash(new string('a', 128)));
    }

    [Fact]
    public void Hashing_options_reject_weak_parameters()
    {
        var options = new PasswordHashingOptions { MemoryKiB = 1024, Iterations = 1, MaxConcurrentHashes = 0 };

        Assert.Equal(3, options.Validate().Count);
        Assert.Empty(new PasswordHashingOptions().Validate());
    }

    [Fact]
    public void Hash_upgrade_keeps_the_password_change_time()
    {
        var created = new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
        var user = User.Create(Guid.CreateVersion7(), Guid.CreateVersion7(), "a@example.com", "old", created);

        user.UpgradePasswordHash("new");

        Assert.Equal("new", user.PasswordHash);
        Assert.Equal(created, user.PasswordChangedAt);
    }
}
