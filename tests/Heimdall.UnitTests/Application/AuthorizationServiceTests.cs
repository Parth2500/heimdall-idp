using System.Buffers.Text;
using System.Net;
using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class AuthorizationServiceTests
{
    private const string Issuer = "https://acme.example.com";
    private const string Callback = "https://app.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryAuthorizationStore _store = new();
    private readonly InMemoryUserStore _users;
    private readonly InMemorySessionStore _sessions;
    private readonly RecordingAuditLog _audit = new();
    private readonly AuthorizationService _service;
    private readonly Client _spa;
    private readonly User _user;

    public AuthorizationServiceTests()
    {
        _users = new InMemoryUserStore();
        _sessions = new InMemorySessionStore { Users = _users };
        var authenticator = new UserAuthenticator(
            _users, new FakePasswordHasher(), new InMemoryLoginThrottleStore(), new LoginThrottleOptions(), _audit, _time);
        var sessions = new SessionService(authenticator, _sessions, _audit, _time);
        _service = new AuthorizationService(_clients, _store, sessions, _audit, _time);
        _spa = AddClient("spa");
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", "hash", Now.AddDays(-1));
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private Client AddClient(
        string clientId,
        string[]? redirectUris = null,
        bool requireConsent = false,
        GrantType[]? grants = null)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            clientId,
            "Single-page app",
            ClientType.Public,
            grants ?? [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "profile", "offline_access"],
            redirectUris ?? [Callback],
            requireConsent,
            overrides: null,
            Now);
        client.Approve();
        _clients.Add(client);
        return client;
    }

    /// <summary>A session that signed in at <paramref name="authTime"/>. Returns the cookie value.</summary>
    private string SignedIn(DateTimeOffset? authTime = null, User? user = null)
    {
        var id = Base64Url.EncodeToString(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        _sessions.Add(Session.Start(TokenHash.Compute(id), "sid-for-tests-00000000", _tenant.Id, (user ?? _user).Id, TimeSpan.FromHours(12), authTime ?? Now));
        return id;
    }

    private static Dictionary<string, string> Valid(params (string Name, string? Value)[] changes)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = "spa",
            ["redirect_uri"] = Callback,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["state"] = "af0ifjsldkj",
            ["nonce"] = "n-0S6_WzA2Mj",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        };
        foreach (var (name, value) in changes)
        {
            if (value is null)
            {
                parameters.Remove(name);
            }
            else
            {
                parameters[name] = value;
            }
        }

        return parameters;
    }

    private Task<AuthorizeOutcome> Authorize(Dictionary<string, string> parameters, string? sessionId = null) =>
        _service.AuthorizeAsync(Context, parameters, sessionId, CancellationToken.None);

    private Task<AuthorizeOutcome> Resume(string? requestId, string? sessionId) =>
        _service.ResumeAsync(Context, requestId, sessionId, CancellationToken.None);

    private static void AssertPage(AuthorizeOutcome outcome, string error, string reason)
    {
        var page = Assert.IsType<AuthorizeErrorPage>(outcome);
        Assert.Equal(error, page.Error);
        Assert.Equal(reason, page.Reason);
    }

    private static void AssertErrorRedirect(AuthorizeOutcome outcome, string error, string reason, string? state = "af0ifjsldkj")
    {
        var redirect = Assert.IsType<AuthorizeRedirect>(outcome);
        Assert.Equal(Callback, redirect.RedirectUri);
        Assert.Equal(reason, redirect.Reason);
        var expected = new List<KeyValuePair<string, string>> { new("error", error) };
        if (state is not null)
        {
            expected.Add(new("state", state));
        }

        expected.Add(new("iss", Issuer));
        Assert.Equal(expected, redirect.Parameters);
    }

    private static string CodeOf(AuthorizeOutcome outcome)
    {
        var redirect = Assert.IsType<AuthorizeRedirect>(outcome);
        Assert.Null(redirect.Reason);
        Assert.Equal(Callback, redirect.RedirectUri);
        var code = Assert.Single(redirect.Parameters, p => p.Key == "code").Value;
        Assert.Equal(Issuer, Assert.Single(redirect.Parameters, p => p.Key == "iss").Value);
        return code;
    }

    // 1. Errors before the client and the redirect URI are proven: shown by Heimdall, never redirected.

    [Fact]
    public async Task Suspended_tenant_gets_an_error_page()
    {
        _tenant.Suspend();

        AssertPage(await Authorize(Valid()), OAuthError.InvalidRequestCode, "tenant suspended");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Missing_client_id_gets_an_error_page(string? clientId)
    {
        AssertPage(await Authorize(Valid(("client_id", clientId))), OAuthError.InvalidRequestCode, "client_id missing");
    }

    [Fact]
    public async Task Unknown_client_gets_an_error_page()
    {
        AssertPage(await Authorize(Valid(("client_id", "no-such-client"))), OAuthError.InvalidClientCode, "unknown client");
    }

    [Fact]
    public async Task Disabled_client_gets_an_error_page()
    {
        _spa.Disable();

        AssertPage(await Authorize(Valid()), OAuthError.InvalidClientCode, "client status Disabled");
    }

    [Theory]
    [InlineData("https://app.example.com/callback/")]
    [InlineData("https://APP.example.com/callback")]
    [InlineData("https://app.example.com/callback?x=1")]
    [InlineData("https://evil.example.com/callback")]
    public async Task Redirect_uri_that_is_not_an_exact_match_gets_an_error_page(string redirectUri)
    {
        AssertPage(
            await Authorize(Valid(("redirect_uri", redirectUri))),
            OAuthError.InvalidRequestCode,
            "redirect_uri not registered (exact match)");
    }

    [Fact]
    public async Task Missing_redirect_uri_uses_the_only_registered_one()
    {
        var outcome = await Authorize(Valid(("redirect_uri", null)));

        Assert.IsType<AuthorizeLogin>(outcome);
        Assert.Equal(Callback, Assert.Single(_store.Requests).RedirectUri);
    }

    [Fact]
    public async Task Missing_redirect_uri_with_several_registered_gets_an_error_page()
    {
        AddClient("two-uris", [Callback, "https://app.example.com/other"]);

        AssertPage(
            await Authorize(Valid(("client_id", "two-uris"), ("redirect_uri", null))),
            OAuthError.InvalidRequestCode,
            "redirect_uri missing");
    }

    // 2. Errors after that point go to the registered redirect URI, with state and iss.

    [Fact]
    public async Task State_of_the_maximum_length_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("state", new string('s', AuthorizationRequest.MaxClientValueLength)))));
    }

    [Fact]
    public async Task Oversized_state_is_not_echoed_back()
    {
        var outcome = await Authorize(Valid(("state", new string('s', AuthorizationRequest.MaxClientValueLength + 1))));

        AssertErrorRedirect(outcome, OAuthError.InvalidRequestCode, "state too long", state: null);
    }

    [Fact]
    public async Task Error_without_state_has_only_error_and_iss()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("state", null), ("response_type", "token"))),
            "unsupported_response_type",
            "response_type is not code",
            state: null);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("token")]
    [InlineData("code id_token")]
    public async Task Response_type_other_than_code_is_refused(string? responseType)
    {
        AssertErrorRedirect(await Authorize(Valid(("response_type", responseType))), "unsupported_response_type", "response_type is not code");
    }

    [Fact]
    public async Task Response_mode_query_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("response_mode", "query"))));
    }

    [Theory]
    [InlineData("fragment")]
    [InlineData("form_post")]
    public async Task Other_response_modes_are_refused(string mode)
    {
        AssertErrorRedirect(await Authorize(Valid(("response_mode", mode))), OAuthError.InvalidRequestCode, "response_mode not supported");
    }

    [Fact]
    public async Task Request_object_is_refused()
    {
        AssertErrorRedirect(await Authorize(Valid(("request", "eyJ..."))), "request_not_supported", "request object");
    }

    [Fact]
    public async Task Request_uri_is_refused()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("request_uri", "urn:ietf:params:oauth:request_uri:x"))),
            "request_uri_not_supported",
            "request_uri");
    }

    [Fact]
    public async Task Client_without_the_grant_is_unauthorized_client()
    {
        var service = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "billing", "Billing", ClientType.Confidential, [GrantType.ClientCredentials],
            ["openid"], [Callback], requireConsent: false, overrides: null, Now, ["https://api.example.com"]);
        service.Approve();
        _clients.Add(service, ("secret", null));

        AssertErrorRedirect(
            await Authorize(Valid(("client_id", "billing"))),
            OAuthError.UnauthorizedClientCode,
            "authorization_code not allowed");
    }

    [Theory]
    [InlineData(null)] // RFC 7636: a missing method means plain.
    [InlineData("plain")]
    [InlineData("s256")]
    public async Task Code_challenge_method_other_than_S256_is_refused(string? method)
    {
        AssertErrorRedirect(
            await Authorize(Valid(("code_challenge_method", method))),
            OAuthError.InvalidRequestCode,
            "code_challenge_method is not S256");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("too-short")]
    public async Task Missing_or_malformed_code_challenge_is_refused(string? challenge)
    {
        AssertErrorRedirect(
            await Authorize(Valid(("code_challenge", challenge))),
            OAuthError.InvalidRequestCode,
            "code_challenge malformed or missing");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("openid \"x\"")]
    public async Task Missing_or_malformed_scope_is_refused(string? scope)
    {
        AssertErrorRedirect(await Authorize(Valid(("scope", scope))), OAuthError.InvalidScopeCode, "scope malformed or missing");
    }

    [Fact]
    public async Task Scope_that_is_not_allowed_is_refused_not_reduced()
    {
        AssertErrorRedirect(await Authorize(Valid(("scope", "openid admin"))), OAuthError.InvalidScopeCode, "scope not allowed for client");
    }

    [Fact]
    public async Task Offline_access_without_the_refresh_grant_is_refused()
    {
        AddClient("no-refresh", grants: [GrantType.AuthorizationCode]);

        AssertErrorRedirect(
            await Authorize(Valid(("client_id", "no-refresh"), ("scope", "openid offline_access"))),
            OAuthError.InvalidScopeCode,
            "offline_access without the refresh_token grant");
    }

    [Fact]
    public async Task Offline_access_with_the_refresh_grant_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("scope", "openid offline_access"))));
    }

    [Theory]
    [InlineData("consent")]
    [InlineData("select_account")]
    [InlineData("none login")]
    [InlineData("login login")]
    public async Task Unsupported_or_combined_prompt_is_refused(string prompt)
    {
        AssertErrorRedirect(await Authorize(Valid(("prompt", prompt))), OAuthError.InvalidRequestCode, "prompt not supported");
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData(" 5")]
    [InlineData("1.5")]
    [InlineData("99999999999")]
    public async Task Malformed_max_age_is_refused(string maxAge)
    {
        AssertErrorRedirect(await Authorize(Valid(("max_age", maxAge))), OAuthError.InvalidRequestCode, "max_age malformed");
    }

    [Fact]
    public async Task Nonce_of_the_maximum_length_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("nonce", new string('n', AuthorizationRequest.MaxClientValueLength)))));
    }

    [Fact]
    public async Task Oversized_nonce_is_refused()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("nonce", new string('n', AuthorizationRequest.MaxClientValueLength + 1)))),
            OAuthError.InvalidRequestCode,
            "nonce too long");
    }

    [Theory]
    [InlineData("too-short")]
    [InlineData("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4=")]
    [InlineData("0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I")]
    public async Task Malformed_dpop_jkt_is_refused(string dpopJkt)
    {
        AssertErrorRedirect(await Authorize(Valid(("dpop_jkt", dpopJkt))), OAuthError.InvalidRequestCode, "dpop_jkt malformed");
    }

    // 3. A valid request: sign-in, consent, and the code.

    [Fact]
    public async Task Without_a_session_the_request_is_stored_and_the_user_signs_in()
    {
        var outcome = await Authorize(Valid(("scope", "openid profile openid"), ("max_age", "300")));

        var request = Assert.Single(_store.Requests);
        Assert.Equal(new AuthorizeLogin(request.Id), outcome);
        Assert.Equal(_tenant.Id, request.TenantId);
        Assert.Equal(_spa.Id, request.ClientPk);
        Assert.Equal(Callback, request.RedirectUri);
        Assert.Equal("openid profile", request.Scope);
        Assert.Equal("af0ifjsldkj", request.State);
        Assert.Equal("n-0S6_WzA2Mj", request.Nonce);
        Assert.Equal(Challenge, request.CodeChallenge);
        Assert.False(request.ForceLogin);
        Assert.Equal(TimeSpan.FromMinutes(5), request.MaxAge);
        Assert.Equal(Now, request.CreatedAt);
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Signed_in_user_gets_a_code_with_state_and_iss()
    {
        var authTime = Now.AddMinutes(-3);
        var sessionId = SignedIn(authTime);

        var outcome = await Authorize(Valid(), sessionId);

        var code = CodeOf(outcome);
        Assert.Equal(43, code.Length);
        Assert.Equal(
            [new("code", code), new("state", "af0ifjsldkj"), new("iss", Issuer)],
            ((AuthorizeRedirect)outcome).Parameters);

        var stored = Assert.Single(_store.Codes);
        Assert.Equal(TokenHash.Compute(code), stored.CodeHash);
        Assert.Equal(_tenant.Id, stored.TenantId);
        Assert.Equal(_spa.Id, stored.ClientPk);
        Assert.Equal(_user.Id, stored.UserId);
        Assert.Equal(Callback, stored.RedirectUri);
        Assert.Equal("openid profile", stored.Scope);
        Assert.Equal(Challenge, stored.CodeChallenge);
        Assert.Equal("n-0S6_WzA2Mj", stored.Nonce);
        Assert.Equal(Assert.Single(_sessions.Sessions).Sid, stored.Sid);
        Assert.Equal(authTime, stored.AuthTime);
        Assert.Equal(Now, stored.CreatedAt);

        // A signed-in user gets the code at once, so the request is never stored: one save, for the code only.
        Assert.Empty(_store.Requests);
        Assert.Equal(1, _store.SaveCount);

        var issued = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.CodeIssued, issued.Type);
        Assert.Equal(_user.Id, issued.SubjectUserId);
        Assert.Equal(_spa.Id, issued.ClientPk);
        Assert.Equal("corr-1", issued.CorrelationId);
        Assert.Equal(Now, issued.OccurredAt);
        Assert.Equal("spa", issued.Data["client_id"]);
        Assert.Equal("openid profile", issued.Data["scope"]);
    }

    private const string DpopJkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    [Fact]
    public async Task Dpop_jkt_goes_with_the_code_when_the_user_is_signed_in()
    {
        CodeOf(await Authorize(Valid(("dpop_jkt", DpopJkt)), SignedIn()));

        Assert.Equal(DpopJkt, Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Dpop_jkt_is_stored_with_the_request_and_reaches_the_code_after_sign_in()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("dpop_jkt", DpopJkt))));
        var request = Assert.Single(_store.Requests);
        Assert.Equal(DpopJkt, request.DpopKeyThumbprint);

        CodeOf(await Resume(request.Id.ToString(), SignedIn()));

        Assert.Equal(DpopJkt, Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Without_dpop_jkt_the_code_is_not_bound()
    {
        CodeOf(await Authorize(Valid(), SignedIn()));

        Assert.Null(Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Code_without_state_has_only_code_and_iss()
    {
        var outcome = await Authorize(Valid(("state", null)), SignedIn());

        var code = CodeOf(outcome);
        Assert.Equal([new("code", code), new("iss", Issuer)], ((AuthorizeRedirect)outcome).Parameters);
    }

    [Fact]
    public async Task Each_code_is_new_random_text()
    {
        var sessionId = SignedIn();

        var first = CodeOf(await Authorize(Valid(), sessionId));
        var second = CodeOf(await Authorize(Valid(), sessionId));

        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task Prompt_none_without_a_session_is_login_required_and_stores_nothing()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("prompt", "none"))),
            "login_required",
            "prompt=none without a usable session");
        Assert.Empty(_store.Requests);
        Assert.Equal(0, _store.SaveCount);
    }

    [Fact]
    public async Task Prompt_none_with_a_session_returns_a_code_without_a_stored_request()
    {
        CodeOf(await Authorize(Valid(("prompt", "none")), SignedIn()));

        Assert.Empty(_store.Requests);
        Assert.Single(_store.Codes);
        Assert.Equal(1, _store.SaveCount);
    }

    [Fact]
    public async Task Prompt_login_asks_again_even_with_a_session()
    {
        var outcome = await Authorize(Valid(("prompt", "login")), SignedIn());

        var request = Assert.Single(_store.Requests);
        Assert.Equal(new AuthorizeLogin(request.Id), outcome);
        Assert.True(request.ForceLogin);
    }

    [Fact]
    public async Task Prompt_login_then_a_new_sign_in_gives_a_code()
    {
        var request = (AuthorizeLogin)await Authorize(Valid(("prompt", "login")), SignedIn());
        _time.Advance(TimeSpan.FromSeconds(30));
        var fresh = SignedIn(_time.GetUtcNow());

        CodeOf(await Resume(request.RequestId.ToString(), fresh));
    }

    [Fact]
    public async Task Max_age_asks_again_when_the_sign_in_is_older()
    {
        var sessionId = SignedIn(Now.AddMinutes(-2));

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("max_age", "60")), sessionId));
        CodeOf(await Authorize(Valid(("max_age", "120")), sessionId));
    }

    [Fact]
    public async Task Max_age_zero_always_asks_again()
    {
        _time.Advance(TimeSpan.FromSeconds(1));

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("max_age", "0")), SignedIn(Now)));
    }

    [Fact]
    public async Task Client_that_requires_consent_asks_the_user()
    {
        AddClient("consent-app", requireConsent: true);

        var outcome = await Authorize(Valid(("client_id", "consent-app")), SignedIn());

        var request = Assert.Single(_store.Requests);
        Assert.Equal(new AuthorizeConsent(request.Id), outcome);
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Prompt_none_with_required_consent_is_consent_required()
    {
        AddClient("consent-app", requireConsent: true);

        AssertErrorRedirect(
            await Authorize(Valid(("client_id", "consent-app"), ("prompt", "none")), SignedIn()),
            "consent_required",
            "client requires consent");
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Approval_then_resume_issues_the_code()
    {
        AddClient("consent-app", requireConsent: true);
        var sessionId = SignedIn();
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), sessionId);
        _store.Requests.Single().DecideConsent(_user.Id, approved: true);

        CodeOf(await Resume(request.RequestId.ToString(), sessionId));
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task Denial_ends_the_request_with_access_denied()
    {
        AddClient("consent-app", requireConsent: true);
        var sessionId = SignedIn();
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), sessionId);
        _store.Requests.Single().DecideConsent(_user.Id, approved: false);

        AssertErrorRedirect(await Resume(request.RequestId.ToString(), sessionId), "access_denied", "user denied consent");

        Assert.Empty(_store.Requests);
        Assert.Empty(_store.Codes);
        AssertPage(await Resume(request.RequestId.ToString(), sessionId), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task Denial_that_loses_a_race_is_request_already_used()
    {
        AddClient("consent-app", requireConsent: true);
        var sessionId = SignedIn();
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), sessionId);
        _store.Requests.Single().DecideConsent(_user.Id, approved: false);
        _store.LoseNextSave = true;

        AssertPage(await Resume(request.RequestId.ToString(), sessionId), OAuthError.InvalidRequestCode, "request already used");
    }

    [Fact]
    public async Task Decision_of_another_user_does_not_count()
    {
        AddClient("consent-app", requireConsent: true);
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), SignedIn());
        _store.Requests.Single().DecideConsent(_user.Id, approved: true);
        var bob = User.Create(Guid.CreateVersion7(), _tenant.Id, "bob@example.com", "hash", Now.AddDays(-1));
        _users.Add(bob);

        var outcome = await Resume(request.RequestId.ToString(), SignedIn(user: bob));

        Assert.Equal(new AuthorizeConsent(request.RequestId), outcome);
    }

    // 4. Resume of a stored request.

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-guid")]
    public async Task Malformed_request_id_gets_an_error_page(string? requestId)
    {
        AssertPage(await Resume(requestId, SignedIn()), OAuthError.InvalidRequestCode, "request_id malformed");
    }

    [Fact]
    public async Task Unknown_request_gets_an_error_page()
    {
        AssertPage(await Resume(Guid.CreateVersion7().ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task Request_works_until_one_tick_before_it_expires()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _time.Advance(AuthorizationRequest.Lifetime - TimeSpan.FromTicks(1));

        CodeOf(await Resume(request.RequestId.ToString(), SignedIn(_time.GetUtcNow())));
    }

    [Fact]
    public async Task Expired_request_gets_an_error_page()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _time.Advance(AuthorizationRequest.Lifetime);

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn(_time.GetUtcNow())), OAuthError.InvalidRequestCode, "request expired");
    }

    [Fact]
    public async Task Resume_without_a_session_returns_to_sign_in()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());

        Assert.Equal(request, await Resume(request.RequestId.ToString(), null));
    }

    [Fact]
    public async Task Resume_after_the_client_was_disabled_gets_an_error_page()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _spa.Disable();

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn()), OAuthError.InvalidClientCode, "client changed during sign-in");
    }

    [Fact]
    public async Task Request_of_another_tenant_is_unknown()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        var stored = _store.Requests.Single();
        _store.Requests.Clear();
        _store.Requests.Add(AuthorizationRequest.Create(
            stored.Id, Guid.CreateVersion7(), stored.ClientPk, stored.RedirectUri, stored.Scope, stored.State, stored.Nonce,
            stored.CodeChallenge, stored.ForceLogin, stored.MaxAge, stored.CreatedAt));

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task One_request_gives_one_code()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        var sessionId = SignedIn();
        CodeOf(await Resume(request.RequestId.ToString(), sessionId));

        AssertPage(await Resume(request.RequestId.ToString(), sessionId), OAuthError.InvalidRequestCode, "request unknown or used");
        Assert.Single(_store.Codes);
    }

    [Fact]
    public async Task Resume_that_loses_a_race_gets_request_already_used_and_no_code()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _store.LoseNextSave = true;

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request already used");
        Assert.Empty(_store.Codes);
        Assert.Empty(_audit.Events);
    }
}
