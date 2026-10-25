using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Domain;

/// <summary>D29: the public session ID is 22 base64url characters, and every holder of it checks the format.</summary>
public class SessionSidTests
{
    private const string Valid = "sid-for-tests-00000000";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 26, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Id = Guid.CreateVersion7();
    private static readonly TokenLifetimes Lifetimes = new(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(30));

    [Theory]
    [InlineData("sid-for-tests-00000000", true)]
    [InlineData("AAAAAAAAAAAAAAAAAAAA_-", true)]
    [InlineData("sid-for-tests-0000000", false)]
    [InlineData("sid-for-tests-000000000", false)]
    [InlineData("sid+for/tests=00000000", false)]
    [InlineData("sid for tests 00000000", false)]
    [InlineData("sid-for-tests-0000000é", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Format_is_22_base64url_characters(string? value, bool valid) =>
        Assert.Equal(valid, SessionSid.IsValid(value));

    [Fact]
    public void Require_returns_a_valid_value_unchanged() =>
        Assert.Equal(Valid, SessionSid.Require(Valid, "sid"));

    [Fact]
    public void Require_names_the_parameter_of_a_bad_value()
    {
        var error = Assert.Throws<DomainException>(() => SessionSid.Require("short", "the sid"));
        Assert.StartsWith("the sid ", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Session_keeps_its_sid() =>
        Assert.Equal(Valid, Session.Start(TokenHash.Compute("s"), Valid, Id, Id, TimeSpan.FromHours(1), Now).Sid);

    [Fact]
    public void Session_refuses_a_malformed_sid() =>
        Assert.Throws<DomainException>(() => Session.Start(TokenHash.Compute("s"), "short", Id, Id, TimeSpan.FromHours(1), Now));

    [Fact]
    public void Code_keeps_its_sid() =>
        Assert.Equal(Valid, NewCode(Valid).Sid);

    [Fact]
    public void Code_refuses_a_malformed_sid() =>
        Assert.Throws<DomainException>(() => NewCode("short"));

    [Fact]
    public void Family_keeps_its_sid() =>
        Assert.Equal(Valid, TokenFamily.Start(Id, Id, Id, Id, Id, "openid", Lifetimes, Now, sid: Valid).Sid);

    [Fact]
    public void Family_without_a_sid_is_from_an_older_code() =>
        Assert.Null(TokenFamily.Start(Id, Id, Id, Id, Id, "openid", Lifetimes, Now).Sid);

    [Fact]
    public void Family_refuses_a_malformed_sid() =>
        Assert.Throws<DomainException>(() => TokenFamily.Start(Id, Id, Id, Id, Id, "openid", Lifetimes, Now, sid: "short"));

    private static AuthorizationCode NewCode(string sid) =>
        AuthorizationCode.Create(Id, Id, Id, Id, TokenHash.Compute("c"), "https://app.example.com/callback", "openid", Challenge, null, Now, Now, sid);
}
