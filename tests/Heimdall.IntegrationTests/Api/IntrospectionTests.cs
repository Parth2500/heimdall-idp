using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// Introspection (RFC 7662, D36 to D39) with real tokens: a resource server sees a sign-out before the access token's
/// exp. Each test maps to a row of the /introspect table in the threat model.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class IntrospectionTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Api = "https://api.example.com";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public IntrospectionTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser, HttpClient Http, Guid WebAppPk) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    private async Task<Flow> SetUpAsync(params string[] resourceAudiences)
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var webApp = await api.AddWebClientAsync(tenant, audiences: [Api]);
        await api.AddUserAsync(tenant, Email, Password);
        await api.SetResourceAudiencesAsync(tenant, resourceAudiences.Length > 0 ? resourceAudiences : [Api]);
        var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return new Flow(api, tenant, browser, api.ClientFor(tenant.Host), webApp.Id);
    }

    private static async Task<JsonElement> SignInAsync(Flow flow)
    {
        using var authorize = await flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        }));
        var location = authorize.Headers.Location!.OriginalString;
        var code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
        using var token = await flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", "web-app"),
        ]));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        return JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement;
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Response)> IntrospectAsync(
        Flow flow,
        string token,
        bool authenticate = true)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/introspect")
        {
            Content = new FormUrlEncodedContent(authenticate ? [new("token", token)] : [new("token", token), new("client_id", "web-app")]),
        };
        if (authenticate)
        {
            request.Headers.Authorization = HeimdallApiFactory.Basic(flow.Tenant.ClientId, flow.Tenant.ClientSecret);
        }

        var response = await flow.Http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, text.Length > 0 ? JsonDocument.Parse(text).RootElement : default, response);
    }

    [DockerFact]
    public async Task Discovery_names_the_introspection_endpoint()
    {
        await using var flow = await SetUpAsync();

        var document = JsonDocument.Parse(await flow.Http.GetStringAsync(".well-known/openid-configuration")).RootElement;

        Assert.Equal(flow.Tenant.Issuer + "/oauth/v1/introspect", document.GetProperty("introspection_endpoint").GetString());
        Assert.Equal(["client_secret_basic"], document.GetProperty("introspection_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()));
    }

    [DockerFact]
    public async Task Access_token_for_a_served_audience_is_active_with_its_claims()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);

        var (status, body, response) = await IntrospectAsync(flow, tokens.GetProperty("access_token").GetString()!);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.True(body.GetProperty("active").GetBoolean());
        Assert.Equal("web-app", body.GetProperty("client_id").GetString());
        Assert.Equal(Api, body.GetProperty("aud").GetString());
        Assert.Equal(flow.Tenant.Issuer, body.GetProperty("iss").GetString());
        Assert.Equal("openid offline_access", body.GetProperty("scope").GetString());
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal(300, body.GetProperty("exp").GetInt64() - body.GetProperty("iat").GetInt64());
        Assert.False(body.TryGetProperty("cnf", out _));
    }

    [DockerFact]
    public async Task Sign_out_makes_the_access_token_inactive_before_its_exp()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);
        var access = tokens.GetProperty("access_token").GetString()!;

        using (var logout = await flow.Browser.SendAsync(HttpMethod.Get, "oauth/v1/logout?id_token_hint=" + Uri.EscapeDataString(tokens.GetProperty("id_token").GetString()!)))
        {
            Assert.Equal(HttpStatusCode.Found, logout.StatusCode);
        }

        var (status, body, _) = await IntrospectAsync(flow, access);

        // D38: the family read sees the sign-out at once. The answer says nothing about why.
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("""{"active":false}""", body.GetRawText());
    }

    [DockerFact]
    public async Task Revoked_refresh_token_family_makes_the_access_token_inactive()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);
        using (var revoke = await flow.Http.PostAsync("oauth/v1/revoke", new FormUrlEncodedContent(
        [
            new("token", tokens.GetProperty("refresh_token").GetString()!),
            new("client_id", "web-app"),
        ])))
        {
            Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        }

        var (_, body, _) = await IntrospectAsync(flow, tokens.GetProperty("access_token").GetString()!);

        Assert.False(body.GetProperty("active").GetBoolean());
    }

    [DockerFact]
    public async Task Token_of_a_client_that_an_admin_disabled_is_inactive()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);
        await flow.Api.DisableClientAsync(flow.Tenant, flow.WebAppPk);

        var (_, body, _) = await IntrospectAsync(flow, tokens.GetProperty("access_token").GetString()!);

        Assert.Equal("""{"active":false}""", body.GetRawText());
    }

    [DockerFact]
    public async Task Token_for_an_audience_that_the_caller_does_not_serve_is_inactive()
    {
        await using var flow = await SetUpAsync("https://other.example.com");
        var tokens = await SignInAsync(flow);

        var (_, body, _) = await IntrospectAsync(flow, tokens.GetProperty("access_token").GetString()!);

        Assert.Equal("""{"active":false}""", body.GetRawText());
    }

    [DockerFact]
    public async Task Expired_access_token_is_inactive()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);
        flow.Api.Time.Advance(TimeSpan.FromMinutes(5));

        var (_, body, _) = await IntrospectAsync(flow, tokens.GetProperty("access_token").GetString()!);

        Assert.False(body.GetProperty("active").GetBoolean());
    }

    [DockerFact]
    public async Task Refresh_token_of_another_client_is_inactive()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);

        var (_, body, _) = await IntrospectAsync(flow, tokens.GetProperty("refresh_token").GetString()!);

        Assert.Equal("""{"active":false}""", body.GetRawText());
    }

    [DockerFact]
    public async Task Own_client_credentials_token_is_active_without_a_family()
    {
        await using var flow = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(flow.Tenant.ClientId, flow.Tenant.ClientSecret);
        using var token = await flow.Http.SendAsync(request);
        var access = JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("access_token").GetString()!;

        var (_, body, _) = await IntrospectAsync(flow, access);

        Assert.True(body.GetProperty("active").GetBoolean());
        Assert.Equal(flow.Tenant.ClientId, body.GetProperty("client_id").GetString());
    }

    [DockerFact]
    public async Task Public_client_is_refused()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInAsync(flow);

        var (status, body, response) = await IntrospectAsync(flow, tokens.GetProperty("access_token").GetString()!, authenticate: false);

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
        Assert.Equal("Basic", response.Headers.WwwAuthenticate.Single().Scheme);
    }

    [DockerFact]
    public async Task Token_in_the_query_string_is_refused()
    {
        await using var flow = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/introspect?token=abc")
        {
            Content = new FormUrlEncodedContent([new("token", "abc")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(flow.Tenant.ClientId, flow.Tenant.ClientSecret);

        using var response = await flow.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
