using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Domain;

public class TokenTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly TokenLifetimes Lifetimes =
        new(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(30));

    private static AuthorizationCode NewCode(string challenge = Challenge, string? dpopKeyThumbprint = null) =>
        AuthorizationCode.Create(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            TokenHash.Compute("code-value"),
            "https://app.example.com/callback",
            "openid profile",
            challenge,
            nonce: "n-0S6_WzA2Mj",
            authTime: Now,
            now: Now,
            sid: "sid-for-tests-00000000",
            dpopKeyThumbprint);

    private static TokenFamily NewFamily(string scope = "openid profile offline_access") =>
        TokenFamily.Start(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            scope,
            Lifetimes,
            Now);

    // Authorization code

    [Fact]
    public void Code_dpop_key_thumbprint_must_be_a_thumbprint()
    {
        Assert.Throws<DomainException>(() => NewCode(dpopKeyThumbprint: new string('a', 42)));
        Assert.Equal(new string('a', 43), NewCode(dpopKeyThumbprint: new string('a', 43)).DpopKeyThumbprint);
        Assert.Null(NewCode().DpopKeyThumbprint);
    }

    [Fact]
    public void Code_expires_after_five_minutes()
    {
        var code = NewCode();

        Assert.Equal(Now.AddMinutes(5), code.ExpiresAt);
    }

    [Fact]
    public void Code_redeems_once_and_records_the_family()
    {
        var code = NewCode();
        var familyId = Guid.CreateVersion7();

        var result = code.Redeem(familyId, Now.AddMinutes(1));

        Assert.Equal(CodeRedemptionResult.Redeemed, result);
        Assert.Equal(familyId, code.FamilyId);
        Assert.Equal(Now.AddMinutes(1), code.RedeemedAt);
    }

    [Fact]
    public void Second_redemption_is_reported_as_reuse_and_keeps_the_first_family()
    {
        var code = NewCode();
        var firstFamily = Guid.CreateVersion7();
        code.Redeem(firstFamily, Now.AddMinutes(1));

        var result = code.Redeem(Guid.CreateVersion7(), Now.AddMinutes(2));

        Assert.Equal(CodeRedemptionResult.AlreadyRedeemed, result);
        Assert.Equal(firstFamily, code.FamilyId);
    }

    [Fact]
    public void Reuse_is_reported_even_after_the_code_expired()
    {
        var code = NewCode();
        code.Redeem(Guid.CreateVersion7(), Now.AddMinutes(1));

        var result = code.Redeem(Guid.CreateVersion7(), Now.AddMinutes(10));

        Assert.Equal(CodeRedemptionResult.AlreadyRedeemed, result);
    }

    [Fact]
    public void Expired_code_cannot_be_redeemed()
    {
        var code = NewCode();

        var result = code.Redeem(Guid.CreateVersion7(), Now.AddMinutes(5));

        Assert.Equal(CodeRedemptionResult.Expired, result);
        Assert.Null(code.RedeemedAt);
        Assert.Null(code.FamilyId);
    }

    [Theory]
    [InlineData("plain-challenge")]
    [InlineData("")]
    public void Code_needs_an_S256_challenge(string challenge)
    {
        Assert.Throws<DomainException>(() => NewCode(challenge));
    }

    // Token family

    [Fact]
    public void New_family_gets_idle_and_absolute_limits()
    {
        var family = NewFamily();

        Assert.Equal(Now.AddDays(7), family.IdleExpiresAt);
        Assert.Equal(Now.AddDays(30), family.AbsoluteExpiresAt);
        Assert.True(family.IsActive(Now));
    }

    [Fact]
    public void Family_ends_when_idle_time_runs_out()
    {
        var family = NewFamily();

        Assert.False(family.IsActive(Now.AddDays(7)));
    }

    [Fact]
    public void Rotation_moves_the_idle_limit()
    {
        var family = NewFamily();
        var later = Now.AddDays(6);

        family.ExtendIdle(Lifetimes.RefreshIdle, later);

        Assert.Equal(later.AddDays(7), family.IdleExpiresAt);
        Assert.Equal(Now.AddDays(30), family.AbsoluteExpiresAt);
    }

    [Fact]
    public void Idle_limit_never_passes_the_absolute_limit()
    {
        var family = NewFamily();
        var near = Now.AddDays(29);
        family.ExtendIdle(Lifetimes.RefreshIdle, Now.AddDays(6));
        family.ExtendIdle(Lifetimes.RefreshIdle, Now.AddDays(12));
        family.ExtendIdle(Lifetimes.RefreshIdle, Now.AddDays(18));
        family.ExtendIdle(Lifetimes.RefreshIdle, Now.AddDays(24));

        family.ExtendIdle(Lifetimes.RefreshIdle, near);

        Assert.Equal(family.AbsoluteExpiresAt, family.IdleExpiresAt);
    }

    [Fact]
    public void Idle_limit_longer_than_absolute_at_start_is_capped()
    {
        var family = TokenFamily.Start(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            "openid",
            new TokenLifetimes(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(1)),
            Now);

        Assert.Equal(family.AbsoluteExpiresAt, family.IdleExpiresAt);
    }

    [Fact]
    public void Revoked_family_is_inactive_and_cannot_be_extended()
    {
        var family = NewFamily();
        family.Revoke(FamilyRevocationReason.ReuseDetected, Now.AddHours(1));

        Assert.False(family.IsActive(Now.AddHours(1)));
        Assert.Throws<DomainException>(() => family.ExtendIdle(Lifetimes.RefreshIdle, Now.AddHours(2)));
    }

    [Fact]
    public void Second_revocation_keeps_the_first_reason()
    {
        var family = NewFamily();
        family.Revoke(FamilyRevocationReason.ReuseDetected, Now.AddHours(1));

        family.Revoke(FamilyRevocationReason.UserLogout, Now.AddHours(2));

        Assert.Equal(FamilyRevocationReason.ReuseDetected, family.RevocationReason);
        Assert.Equal(Now.AddHours(1), family.RevokedAt);
    }

    [Fact]
    public void Refresh_can_keep_or_reduce_scope_but_not_add()
    {
        var family = NewFamily("openid profile");

        Assert.True(family.IsScopeAllowed(["openid", "profile"]));
        Assert.True(family.IsScopeAllowed(["openid"]));
        Assert.False(family.IsScopeAllowed(["openid", "email"]));
    }

    // Refresh token

    [Fact]
    public void Refresh_token_is_used_once()
    {
        var token = RefreshToken.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), TokenHash.Compute("refresh-1"), Now);
        var next = Guid.CreateVersion7();

        var first = token.Use(next, Now.AddMinutes(1));
        var second = token.Use(Guid.CreateVersion7(), Now.AddMinutes(2));

        Assert.Equal(RefreshTokenUseResult.Used, first);
        Assert.Equal(RefreshTokenUseResult.Reused, second);
        Assert.Equal(next, token.ReplacedById);
        Assert.Equal(Now.AddMinutes(1), token.UsedAt);
    }
}
