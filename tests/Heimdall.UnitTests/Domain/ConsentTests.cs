using Heimdall.Domain.Common;
using Heimdall.Domain.Consents;

namespace Heimdall.UnitTests.Domain;

public class ConsentTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private static Consent NewConsent(params string[] scopes) =>
        Consent.Grant(Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), scopes, Now);

    [Fact]
    public void Consent_covers_granted_scopes_only()
    {
        var consent = NewConsent("openid", "profile");

        Assert.True(consent.Covers(["openid"]));
        Assert.True(consent.Covers(["openid", "profile"]));
        Assert.False(consent.Covers(["openid", "email"]));
    }

    [Fact]
    public void Revoked_consent_covers_nothing()
    {
        var consent = NewConsent("openid");

        consent.Revoke(Now.AddMinutes(1));

        Assert.False(consent.Covers(["openid"]));
    }

    [Fact]
    public void Approval_of_an_active_consent_adds_scopes()
    {
        var consent = NewConsent("openid");

        consent.Approve(["email"], Now.AddMinutes(1));

        Assert.True(consent.Covers(["openid", "email"]));
    }

    [Fact]
    public void Approval_after_revocation_does_not_bring_back_old_scopes()
    {
        var consent = NewConsent("openid", "profile");
        consent.Revoke(Now.AddMinutes(1));

        consent.Approve(["openid"], Now.AddMinutes(2));

        Assert.True(consent.Covers(["openid"]));
        Assert.False(consent.Covers(["profile"]));
        Assert.Null(consent.RevokedAt);
    }

    [Fact]
    public void Consent_needs_a_scope()
    {
        Assert.Throws<DomainException>(() => NewConsent());
    }

    [Fact]
    public void Scope_with_white_space_is_rejected()
    {
        Assert.Throws<DomainException>(() => NewConsent("openid profile"));
    }
}
