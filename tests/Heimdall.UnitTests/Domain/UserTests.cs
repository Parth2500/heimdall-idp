using Heimdall.Domain.Common;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Domain;

public class UserTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private static User CreateUser(string email = "Ada@Example.com") =>
        User.Create(Guid.CreateVersion7(), Guid.CreateVersion7(), email, "argon2id$hash", Now);

    [Fact]
    public void Email_is_normalized_to_lowercase()
    {
        var user = CreateUser("  Ada@Example.com ");

        Assert.Equal("Ada@Example.com", user.Email);
        Assert.Equal("ada@example.com", user.EmailNormalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-at-sign")]
    [InlineData("@example.com")]
    [InlineData("ada@")]
    [InlineData("a da@example.com")]
    public void Invalid_email_is_rejected(string email)
    {
        Assert.Throws<DomainException>(() => CreateUser(email));
    }

    [Fact]
    public void Empty_password_hash_is_rejected()
    {
        Assert.Throws<DomainException>(() =>
            User.Create(Guid.CreateVersion7(), Guid.CreateVersion7(), "ada@example.com", " ", Now));
    }

    [Fact]
    public void Changing_the_password_moves_PasswordChangedAt()
    {
        var user = CreateUser();
        var later = Now.AddHours(1);

        user.ChangePassword("argon2id$newhash", later);

        Assert.Equal("argon2id$newhash", user.PasswordHash);
        Assert.Equal(later, user.PasswordChangedAt);
        Assert.Equal(Now, user.CreatedAt);
    }

    [Fact]
    public void New_user_is_active_and_can_be_disabled()
    {
        var user = CreateUser();
        Assert.Equal(UserStatus.Active, user.Status);

        user.Disable();

        Assert.Equal(UserStatus.Disabled, user.Status);
    }
}
