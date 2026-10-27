using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// Pushed authorization requests (RFC 9126, D40 to D43) over HTTP: push, sign in with the request_uri, redeem the code.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class PushedAuthorizationTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public PushedAuthorizationTests(PostgresFixture postgres)
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

    private async Task<Flow> SetUpAsync()
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        await api.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return new Flow(api, tenant, browser, api.ClientFor(tenant.Host));
    }

    private static List<KeyValuePair<string, string>> Parameters(params (string Name, string Value)[] extra)
    {
        var list = new List<KeyValuePair<string, string>>
        {
            new("client_id", "web-app"),
            new("response_type", "code"),
            new("redirect_uri", Callback),
            new("scope", "openid offline_access"),
            new("state", "s1"),
            new("nonce", "n-1"),
            new("code_challenge", Challenge),
            new("code_challenge_method", "S256"),
        };
        foreach (var (name, value) in extra)
        {
            list.RemoveAll(p => p.Key == name);
            list.Add(new(name, value));
        }

        return list;
    }

    private static async Task<HttpResponseMessage> PushAsync(Flow flow, List<KeyValuePair<string, string>> parameters, string? proof = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/par") { Content = new FormUrlEncodedContent(parameters) };
        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        return await flow.Http.SendAsync(request);
    }

    private static async Task<string> RequestUriAsync(Flow flow, string? proof = null, params (string Name, string Value)[] extra)
    {
        using var response = await PushAsync(flow, Parameters(extra), proof);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("request_uri").GetString()!;
    }

    private static Task<HttpResponseMessage> AuthorizeAsync(Flow flow, string requestUri, string clientId = "web-app") =>
        flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["request_uri"] = requestUri,
        }));

    private static string CodeOf(HttpResponseMessage authorize)
    {
        var location = authorize.Headers.Location!.OriginalString;
        Assert.StartsWith(Callback + "?", location, StringComparison.Ordinal);
        return QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
    }

    [DockerFact]
    public async Task Discovery_names_the_par_endpoint()
    {
        await using var flow = await SetUpAsync();

        var document = JsonDocument.Parse(await flow.Http.GetStringAsync(".well-known/openid-configuration")).RootElement;

        Assert.Equal(flow.Tenant.Issuer + "/oauth/v1/par", document.GetProperty("pushed_authorization_request_endpoint").GetString());
        Assert.False(document.GetProperty("require_pushed_authorization_requests").GetBoolean());
    }

    [DockerFact]
    public async Task Push_answers_201_with_a_request_uri_for_60_seconds()
    {
        await using var flow = await SetUpAsync();

        using var response = await PushAsync(flow, Parameters());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Matches("^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$", body.GetProperty("request_uri").GetString());
        Assert.Equal(60, body.GetProperty("expires_in").GetInt32());
    }

    [DockerFact]
    public async Task Pushed_request_signs_in_and_its_code_redeems()
    {
        await using var flow = await SetUpAsync();
        var requestUri = await RequestUriAsync(flow);

        using var authorize = await AuthorizeAsync(flow, requestUri);
        var code = CodeOf(authorize);
        Assert.Contains("state=s1", authorize.Headers.Location!.OriginalString, StringComparison.Ordinal);

        using var token = await flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", "web-app"),
        ]));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        var idToken = JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement.GetProperty("id_token").GetString()!;
        Assert.Equal("n-1", new JsonWebToken(idToken).GetClaim("nonce").Value);
    }

    [DockerFact]
    public async Task Request_uri_works_once()
    {
        await using var flow = await SetUpAsync();
        var requestUri = await RequestUriAsync(flow);
        using (var first = await AuthorizeAsync(flow, requestUri))
        {
            CodeOf(first);
        }

        using var second = await AuthorizeAsync(flow, requestUri);

        Assert.Equal("/account/error?error=invalid_request", second.Headers.Location!.OriginalString);
    }

    [DockerFact]
    public async Task Concurrent_uses_of_one_request_uri_give_one_code()
    {
        await using var flow = await SetUpAsync();
        var requestUri = await RequestUriAsync(flow);

        var locations = await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            using var response = await AuthorizeAsync(flow, requestUri);
            return response.Headers.Location!.OriginalString;
        }));

        Assert.Single(locations, l => l.StartsWith(Callback, StringComparison.Ordinal));
        Assert.Equal(3, locations.Count(l => l == "/account/error?error=invalid_request"));
    }

    [DockerFact]
    public async Task Expired_request_uri_is_refused()
    {
        await using var flow = await SetUpAsync();
        var requestUri = await RequestUriAsync(flow);
        flow.Api.Time.Advance(TimeSpan.FromSeconds(60));

        using var authorize = await AuthorizeAsync(flow, requestUri);

        Assert.Equal("/account/error?error=invalid_request", authorize.Headers.Location!.OriginalString);
    }

    [DockerFact]
    public async Task Invalid_pushed_request_gets_a_json_error_not_a_redirect()
    {
        await using var flow = await SetUpAsync();

        using var response = await PushAsync(flow, Parameters(("scope", "openid admin")));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("""{"error":"invalid_scope"}""", await response.Content.ReadAsStringAsync());
    }

    [DockerFact]
    public async Task Wrong_client_secret_is_401()
    {
        await using var flow = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/par")
        {
            // One client method only: the Basic header, so no client_id in the body.
            Content = new FormUrlEncodedContent(Parameters().Where(p => p.Key != "client_id")),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(flow.Tenant.ClientId, "wrong");

        using var response = await flow.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [DockerFact]
    public async Task Proof_at_the_push_binds_the_code_to_its_key()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();
        using var other = new ClientKey();
        var now = flow.Api.Time.GetUtcNow();
        var requestUri = await RequestUriAsync(flow, key.Proof(flow.Tenant.Issuer + "/oauth/v1/par", now));
        using var authorize = await AuthorizeAsync(flow, requestUri);
        var code = CodeOf(authorize);

        async Task<HttpStatusCode> RedeemAsync(ClientKey with)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
            {
                Content = new FormUrlEncodedContent(
                [
                    new("grant_type", "authorization_code"),
                    new("code", code),
                    new("code_verifier", Verifier),
                    new("redirect_uri", Callback),
                    new("client_id", "web-app"),
                ]),
            };
            request.Headers.Add("DPoP", with.Proof(flow.Tenant.Issuer + "/oauth/v1/token", now));
            using var response = await flow.Http.SendAsync(request);
            return response.StatusCode;
        }

        // RFC 9449, section 10.1: only the key of the proof at PAR redeems the code. Another key does not burn it.
        Assert.Equal(HttpStatusCode.BadRequest, await RedeemAsync(other));
        Assert.Equal(HttpStatusCode.OK, await RedeemAsync(key));
    }

    [DockerFact]
    public async Task Proof_for_another_endpoint_is_refused()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();

        using var response = await PushAsync(flow, Parameters(), key.Proof(flow.Tenant.Issuer + "/oauth/v1/token", flow.Api.Time.GetUtcNow()));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("""{"error":"invalid_dpop_proof"}""", await response.Content.ReadAsStringAsync());
    }
}
