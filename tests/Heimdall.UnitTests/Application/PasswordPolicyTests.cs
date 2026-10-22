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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Empty_password_is_refused(string? password)
    {
        Assert.Equal("The password is empty.", PasswordPolicy.Check(password));
    }

    [Fact]
    public void Refusal_reasons_name_the_limit()
    {
        Assert.Equal("The password must have at least 12 characters.", PasswordPolicy.Check("short"));
        Assert.Equal("The password must have at most 128 characters.", PasswordPolicy.Check(new string('a', 129)));
    }

    [Fact]
    public void Input_of_four_code_units_for_each_allowed_character_is_still_checked()
    {
        // A flag emoji is one character and four UTF-16 code units. 128 flags is the longest such valid password.
        var flags = string.Concat(Enumerable.Repeat("\U0001F1FA\U0001F1F8", 128));

        Assert.Equal(128 * 4, flags.Length);
        Assert.False(PasswordPolicy.IsTooLongToHash(flags));
        Assert.True(PasswordPolicy.IsTooLongToHash(flags + "a"));
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
        var options = new PasswordHashingOptions
        {
            MemoryKiB = 19 * 1024 - 1,
            Iterations = 2,
            MaxConcurrentHashes = 0,
            MaxQueueWait = TimeSpan.FromTicks(-1),
        };

        Assert.Equal(
            [
                "MemoryKiB: the value must be at least 19456 (19 MiB).",
                "Iterations: the value must be at least 3.",
                "MaxConcurrentHashes: the value must be at least 1.",
                "MaxQueueWait: the value must not be negative.",
            ],
            options.Validate());
        Assert.Empty(new PasswordHashingOptions().Validate());
    }

    [Fact]
    public void Hashing_options_accept_the_lowest_allowed_values()
    {
        var options = new PasswordHashingOptions
        {
            MemoryKiB = 19 * 1024,
            Iterations = 3,
            MaxConcurrentHashes = 1,
            MaxQueueWait = TimeSpan.Zero,
        };

        Assert.Empty(options.Validate());
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
