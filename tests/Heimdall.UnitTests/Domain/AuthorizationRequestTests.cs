using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Domain;

public class AuthorizationRequestTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid TenantId = Guid.CreateVersion7();

    private static AuthorizationRequest Request(
        bool forceLogin = false,
        TimeSpan? maxAge = null,
        string? state = "s",
        string challenge = Challenge,
        string? dpopKeyThumbprint = null) =>
        AuthorizationRequest.Create(
            Guid.CreateVersion7(),
            TenantId,
            Guid.CreateVersion7(),
            "https://app.example.com/callback",
            "openid",
            state,
            nonce: null,
            challenge,
            forceLogin,
            maxAge,
            Now,
            dpopKeyThumbprint);

    private static Session SignedInAt(DateTimeOffset authTime) =>
        Session.Start(TokenHash.Compute("session-id-for-tests"), "sid-for-tests-00000000", TenantId, Guid.CreateVersion7(), TimeSpan.FromHours(12), authTime);

    [Fact]
    public void Request_expires_after_ten_minutes()
    {
        var request = Request();

        Assert.False(request.IsExpired(Now + TimeSpan.FromMinutes(10) - TimeSpan.FromTicks(1)));
        Assert.True(request.IsExpired(Now + TimeSpan.FromMinutes(10)));
    }

    [Fact]
    public void Plain_or_malformed_challenge_is_refused()
    {
        Assert.Throws<DomainException>(() => Request(challenge: "plain-text-verifier-is-not-a-challenge"));
    }

    [Fact]
    public void Dpop_key_thumbprint_must_be_a_thumbprint()
    {
        Assert.Throws<DomainException>(() => Request(dpopKeyThumbprint: "not-a-thumbprint"));
        Assert.Equal(
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
            Request(dpopKeyThumbprint: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I").DpopKeyThumbprint);
        Assert.Null(Request().DpopKeyThumbprint);
    }

    [Fact]
    public void Oversized_state_is_refused()
    {
        Assert.Throws<DomainException>(() => Request(state: new string('s', AuthorizationRequest.MaxClientValueLength + 1)));
    }

    [Fact]
    public void Prompt_login_needs_a_sign_in_strictly_after_the_request()
    {
        var request = Request(forceLogin: true);

        Assert.False(request.AcceptsSession(SignedInAt(Now - TimeSpan.FromMinutes(1)), Now));
        Assert.False(request.AcceptsSession(SignedInAt(Now), Now));
        Assert.True(request.AcceptsSession(SignedInAt(Now + TimeSpan.FromSeconds(1)), Now + TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void Max_age_compares_with_the_last_sign_in()
    {
        var request = Request(maxAge: TimeSpan.FromMinutes(5));

        Assert.True(request.AcceptsSession(SignedInAt(Now - TimeSpan.FromMinutes(5)), Now));
        Assert.False(request.AcceptsSession(SignedInAt(Now - TimeSpan.FromMinutes(6)), Now));
    }

    [Fact]
    public void Without_prompt_or_max_age_any_valid_session_is_accepted()
    {
        Assert.True(Request().AcceptsSession(SignedInAt(Now - TimeSpan.FromHours(11)), Now));
    }

    [Fact]
    public void Consent_decision_counts_only_for_the_user_who_decided()
    {
        var request = Request();
        var alice = Guid.CreateVersion7();
        var bob = Guid.CreateVersion7();

        Assert.Null(request.ConsentDecisionOf(alice));
        request.DecideConsent(alice, approved: true);

        Assert.True(request.ConsentDecisionOf(alice));
        Assert.Null(request.ConsentDecisionOf(bob));
    }

    [Fact]
    public void A_later_consent_decision_replaces_the_earlier_one()
    {
        var request = Request();
        var alice = Guid.CreateVersion7();
        var bob = Guid.CreateVersion7();

        request.DecideConsent(alice, approved: true);
        request.DecideConsent(bob, approved: false);

        Assert.Null(request.ConsentDecisionOf(alice));
        Assert.False(request.ConsentDecisionOf(bob));
    }

    // ---- Pushed requests (D41)

    [Fact]
    public void Pushed_request_lives_one_minute()
    {
        var request = AuthorizationRequest.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), "https://app.example.com/cb", "openid", null, null,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", false, null, Now, requestUriHash: TokenHash.Compute("urn:x"));

        Assert.Equal(Now + AuthorizationRequest.PushedLifetime, request.ExpiresAt);
        Assert.Equal(TokenHash.Compute("urn:x"), request.RequestUriHash);
    }

    [Fact]
    public void Browser_request_lives_ten_minutes_and_has_no_request_uri()
    {
        var request = AuthorizationRequest.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), "https://app.example.com/cb", "openid", null, null,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", false, null, Now, promptNone: true);

        Assert.Equal(Now + AuthorizationRequest.Lifetime, request.ExpiresAt);
        Assert.Null(request.RequestUriHash);
        Assert.True(request.PromptNone);
    }

    [Fact]
    public void Prompt_none_with_login_is_refused() =>
        Assert.Throws<DomainException>(() => AuthorizationRequest.Create(
            Guid.CreateVersion7(), Guid.CreateVersion7(), Guid.CreateVersion7(), "https://app.example.com/cb", "openid", null, null,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", forceLogin: true, null, Now, promptNone: true));
}
