using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Heimdall.Api.Endpoints;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// RP-Initiated Logout at <c>/oauth/v1/logout</c> and the confirmation at <c>/session/v1/logout</c>, with real sessions,
/// real ID tokens, and the sign-out transaction in PostgreSQL (D30 to D34).
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class LogoutTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Bye = "https://app.example.com/bye";
    private const string Backchannel = "https://app.example.com/backchannel-logout";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public LogoutTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser, HttpClient Http) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    private sealed record Tokens(string IdToken, string RefreshToken, string Sid);

    private async Task<Flow> SetUpAsync(string? backchannel = null)
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant, postLogoutRedirectUris: [Bye], backchannelLogoutUri: backchannel);
        await api.AddWebClientAsync(tenant, clientId: "other-app", postLogoutRedirectUris: ["https://other.example.com/bye"]);
        await api.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return new Flow(api, tenant, browser, api.ClientFor(tenant.Host));
    }

    private static async Task<HttpResponseMessage> AuthorizeAsync(Flow flow, string clientId = "web-app") =>
        await flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = Callback,
            ["scope"] = "openid offline_access",
            ["state"] = "s1",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        }));

    /// <summary>Signs in to the client: a code, then tokens. Returns the ID token, the refresh token, and its sid.</summary>
    private static async Task<Tokens> SignInToClientAsync(Flow flow, string clientId = "web-app")
    {
        using var authorize = await AuthorizeAsync(flow, clientId);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = authorize.Headers.Location!.OriginalString;
        var code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();

        using var token = await flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", clientId),
        ]));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        var body = JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement;
        var idToken = body.GetProperty("id_token").GetString()!;
        return new Tokens(idToken, body.GetProperty("refresh_token").GetString()!, new JsonWebToken(idToken).GetClaim("sid").Value);
    }

    private static Task<HttpResponseMessage> RefreshAsync(Flow flow, string refreshToken, string clientId = "web-app") =>
        flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
            new("client_id", clientId),
        ]));

    private static Task<HttpResponseMessage> LogoutAsync(Flow flow, params (string Name, string Value)[] parameters) =>
        flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/logout", parameters.Select(p => new KeyValuePair<string, string?>(p.Name, p.Value))));

    private static Task<HttpResponseMessage> ConfirmAsync(Flow flow, string? logoutRequest) =>
        flow.Browser.SendAsync(HttpMethod.Post, "session/v1/logout", JsonContent.Create(new Dictionary<string, string?> { ["logout_request"] = logoutRequest }));

    private static async Task<bool> SessionIsValidAsync(Flow flow)
    {
        using var me = await flow.Browser.MeAsync();
        return me.StatusCode == HttpStatusCode.OK;
    }

    private static async Task<List<TokenFamily>> FamiliesAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.AsNoTracking().ToListAsync();
    }

    private static async Task<List<BackchannelLogoutRecord>> QueuedAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().BackchannelLogouts.AsNoTracking().ToListAsync();
    }

    [DockerFact]
    public async Task Discovery_names_the_end_session_endpoint()
    {
        await using var flow = await SetUpAsync();

        var document = JsonDocument.Parse(await flow.Http.GetStringAsync(".well-known/openid-configuration")).RootElement;

        Assert.Equal(flow.Tenant.Issuer + "/oauth/v1/logout", document.GetProperty("end_session_endpoint").GetString());
        Assert.False(document.GetProperty("frontchannel_logout_supported").GetBoolean());
    }

    [DockerFact]
    public async Task Hint_of_this_session_ends_it_revokes_its_tokens_and_redirects()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken), ("post_logout_redirect_uri", Bye), ("state", "af0ifjsldkj"));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(Bye + "?state=af0ifjsldkj", response.Headers.Location!.OriginalString);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Null(flow.Browser.SessionId);
        Assert.False(await SessionIsValidAsync(flow));

        // D33: the refresh token of that sign-in ends too, and the family records why.
        using var refresh = await RefreshAsync(flow, tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        var family = Assert.Single(await FamiliesAsync(flow));
        Assert.Equal(FamilyRevocationReason.UserLogout, family.RevocationReason);
        Assert.Equal(tokens.Sid, family.Sid);
    }

    [DockerFact]
    public async Task Next_sign_in_asks_for_the_password()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);
        using (var logout = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken)))
        {
            Assert.Equal(HttpStatusCode.Found, logout.StatusCode);
        }

        using var authorize = await AuthorizeAsync(flow);

        Assert.StartsWith("/account/login?request_id=", authorize.Headers.Location!.OriginalString, StringComparison.Ordinal);
    }

    [DockerFact]
    public async Task Expired_hint_still_ends_the_session()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);
        // D30: exp does not count. The ID token lives 5 minutes. The session is still inside its idle limit.
        flow.Api.Time.Advance(TimeSpan.FromMinutes(10));

        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken), ("post_logout_redirect_uri", Bye));

        Assert.Equal(Bye, response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Form_post_works_like_a_get()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await flow.Browser.SendAsync(HttpMethod.Post, "oauth/v1/logout", new FormUrlEncodedContent(
        [
            new("id_token_hint", tokens.IdToken),
            new("post_logout_redirect_uri", Bye),
        ]));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(Bye, response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Without_a_hint_the_user_confirms_first()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", Bye), ("state", "s2"));

        // D31: a cross-site link reaches only the confirm page. The session and the cookie stay.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.OriginalString;
        Assert.StartsWith("/account/logout?logout_request=", location, StringComparison.Ordinal);
        Assert.DoesNotContain("app.example.com", location, StringComparison.Ordinal);
        Assert.NotNull(flow.Browser.SessionId);
        Assert.True(await SessionIsValidAsync(flow));

        var logoutRequest = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["logout_request"].ToString();
        using var confirm = await ConfirmAsync(flow, logoutRequest);

        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var body = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(Bye + "?state=s2", body.GetProperty("redirect_to").GetString());
        Assert.Null(flow.Browser.SessionId);
        Assert.False(await SessionIsValidAsync(flow));
        using var refresh = await RefreshAsync(flow, tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [DockerFact]
    public async Task Hint_of_an_older_session_needs_the_click()
    {
        await using var flow = await SetUpAsync();
        var old = await SignInToClientAsync(flow);
        using (var again = await flow.Browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }

        using var response = await LogoutAsync(flow, ("id_token_hint", old.IdToken), ("post_logout_redirect_uri", Bye));

        Assert.StartsWith("/account/logout?logout_request=", response.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.True(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Changed_logout_request_loses_only_the_redirect()
    {
        await using var flow = await SetUpAsync();
        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", Bye));
        var location = response.Headers.Location!.OriginalString;
        var logoutRequest = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["logout_request"].ToString();

        using var confirm = await ConfirmAsync(flow, logoutRequest[..^2] + (logoutRequest[^2] == 'A' ? "BB" : "AA"));

        var body = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("/account/signed-out?logout=done", body.GetProperty("redirect_to").GetString());
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Unregistered_uri_goes_to_the_signed_out_page()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken), ("post_logout_redirect_uri", "https://evil.example.com/"));

        // D32: no open redirect. The session still ends, because the hint names it.
        Assert.Equal("/account/signed-out?logout=done", response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Uri_of_another_client_goes_to_the_signed_out_page()
    {
        await using var flow = await SetUpAsync();

        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", "https://other.example.com/bye"));

        // The URI is not registered for web-app, so the confirm page gets no target to seal.
        Assert.Equal("/account/logout", response.Headers.Location!.OriginalString);
    }

    [DockerFact]
    public async Task Repeated_parameter_is_an_error_and_ends_nothing()
    {
        await using var flow = await SetUpAsync();

        using var response = await flow.Browser.SendAsync(HttpMethod.Get, "oauth/v1/logout?client_id=web-app&client_id=other-app");

        Assert.Equal("/account/error?error=invalid_request", response.Headers.Location!.OriginalString);
        Assert.True(await SessionIsValidAsync(flow));
        Assert.NotNull(flow.Browser.SessionId);
    }

    [DockerFact]
    public async Task Without_a_session_the_browser_goes_back_at_once()
    {
        await using var flow = await SetUpAsync();
        flow.Browser.Cookies.Remove(SessionEndpoints.SessionCookie);

        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", Bye), ("state", "s3"));

        Assert.Equal(Bye + "?state=s3", response.Headers.Location!.OriginalString);
    }

    [DockerFact]
    public async Task Sign_out_queues_one_backchannel_logout_for_each_client_that_registered_a_uri()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        var tokens = await SignInToClientAsync(flow);
        await SignInToClientAsync(flow);
        await SignInToClientAsync(flow, "other-app");

        using (var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken)))
        {
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        // D34: web-app has two families of this session and one row. other-app registered no URI.
        var queued = Assert.Single(await QueuedAsync(flow));
        Assert.Equal(tokens.Sid, queued.Sid);
        Assert.Equal(0, queued.Attempts);
        Assert.Equal(3, (await FamiliesAsync(flow)).Count(f => f.RevocationReason == FamilyRevocationReason.UserLogout));
    }

    [DockerFact]
    public async Task Concurrent_sign_outs_end_the_session_once()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        var tokens = await SignInToClientAsync(flow);
        var cookie = flow.Browser.SessionId!;

        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            using var browser = new BrowserSession(flow.Api, flow.Tenant.Host);
            browser.Cookies[SessionEndpoints.SessionCookie] = cookie;
            using var response = await browser.SendAsync(HttpMethod.Get, "oauth/v1/logout?id_token_hint=" + Uri.EscapeDataString(tokens.IdToken));
            return response.StatusCode;
        }));

        Assert.All(responses, status => Assert.Equal(HttpStatusCode.Found, status));
        Assert.Single(await QueuedAsync(flow));
    }
}
