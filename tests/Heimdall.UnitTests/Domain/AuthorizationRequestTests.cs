using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Domain;

public class AuthorizationRequestTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid TenantId = Guid.CreateVersion7();

    private static AuthorizationRequest Request(bool forceLogin = false, TimeSpan? maxAge = null, string? state = "s", string challenge = Challenge) =>
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
            Now);

    private static Session SignedInAt(DateTimeOffset authTime) =>
        Session.Start(TokenHash.Compute("session-id-for-tests"), TenantId, Guid.CreateVersion7(), TimeSpan.FromHours(12), authTime);

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
}
