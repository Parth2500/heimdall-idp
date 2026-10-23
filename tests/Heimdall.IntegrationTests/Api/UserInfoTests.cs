using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// <c>/oauth/v1/userinfo</c>. Each test maps to a row of the /userinfo table in the threat model.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class UserInfoTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public UserInfoTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser, HttpClient Http) : IAsyncDisposable
    {
        public string UserInfoUrl => Tenant.Issuer + "/oauth/v1/userinfo";

        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    private sealed record Tokens(string AccessToken, string? IdToken);

    private async Task<Flow> SetUpAsync(HeimdallApiFactory? api = null, string[]? audiences = null)
    {
        api ??= new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant, audiences: audiences);
        await api.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return new Flow(api, tenant, browser, api.ClientFor(tenant.Host));
    }

    /// <summary>Runs /authorize and redeems the code. A null resource asks for the client's default audience.</summary>
    private static async Task<Tokens> GetTokensAsync(Flow flow, string scope, string? resource)
    {
        string code;
        using (var authorize = await flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = scope,
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        })))
        {
            Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
            var location = authorize.Headers.Location!.OriginalString;
            code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
        }

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", "web-app"),
        };
        if (resource is not null)
        {
            form.Add(new("resource", resource));
        }

        using var redeemed = await flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        var body = JsonDocument.Parse(await redeemed.Content.ReadAsStringAsync()).RootElement;
        return new Tokens(
            body.GetProperty("access_token").GetString()!,
            body.TryGetProperty("id_token", out var idToken) ? idToken.GetString() : null);
    }

    private static Task<HttpResponseMessage> CallAsync(Flow flow, string? token, HttpMethod? method = null, string path = "oauth/v1/userinfo")
    {
        var request = new HttpRequestMessage(method ?? HttpMethod.Get, path);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return flow.Http.SendAsync(request);
    }

    private static async Task AssertInvalidTokenAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Equal("""{"error":"invalid_token"}""", await response.Content.ReadAsStringAsync());
    }

    private static string Subject(string jwt) =>
        JsonDocument.Parse(Base64Url.DecodeFromChars(jwt.Split('.')[1])).RootElement.GetProperty("sub").GetString()!;

    [DockerFact]
    public async Task Token_for_userinfo_returns_the_same_sub_as_the_id_token_and_no_other_claims()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid profile", flow.UserInfoUrl);

        using var response = await CallAsync(flow, tokens.AccessToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(Subject(tokens.IdToken!), body.GetProperty("sub").GetString());
        Assert.Equal(["sub"], body.EnumerateObject().Select(p => p.Name));

        await using var scope = flow.Api.Services.CreateAsyncScope();
        var audit = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking()
            .SingleAsync(e => e.TenantId == flow.Tenant.Tenant.Id && e.Type == AuditEventTypes.UserInfoRead);
        Assert.Equal("openid profile", audit.Data["scope"]);
        Assert.DoesNotContain(audit.Data.Values, v => v.Contains(Email, StringComparison.Ordinal));
    }

    [DockerFact]
    public async Task Email_scope_releases_the_email_as_unverified()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid email", flow.UserInfoUrl);

        using var response = await CallAsync(flow, tokens.AccessToken, HttpMethod.Post);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(Email, body.GetProperty("email").GetString());
        Assert.False(body.GetProperty("email_verified").GetBoolean());
    }

    [DockerFact]
    public async Task Client_with_no_registered_audience_gets_a_userinfo_token_by_default()
    {
        await using var flow = await SetUpAsync(audiences: []);
        var tokens = await GetTokensAsync(flow, "openid", resource: null);

        using var response = await CallAsync(flow, tokens.AccessToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [DockerFact]
    public async Task Token_for_a_resource_server_is_refused()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid", resource: null);

        using var response = await CallAsync(flow, tokens.AccessToken);

        await AssertInvalidTokenAsync(response);
    }

    [DockerFact]
    public async Task Id_token_tampered_token_and_alg_none_are_refused()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid", flow.UserInfoUrl);
        var parts = tokens.AccessToken.Split('.');

        // Changing one claim breaks the signature.
        var payload = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1])).Replace("\"openid\"", "\"openid email\"", StringComparison.Ordinal);
        var tampered = parts[0] + "." + Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload)) + "." + parts[2];

        var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0])).RootElement;
        var noneHeader = $$"""{"alg":"none","kid":"{{header.GetProperty("kid").GetString()}}","typ":"at+jwt"}""";
        var algNone = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(noneHeader)) + "." + parts[1] + ".";

        foreach (var token in new[] { tokens.IdToken!, tampered, algNone, "not-a-jwt" })
        {
            using var response = await CallAsync(flow, token);
            await AssertInvalidTokenAsync(response);
        }
    }

    [DockerFact]
    public async Task Expired_token_is_refused()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid", flow.UserInfoUrl);
        flow.Api.Time.Advance(flow.Tenant.Tenant.Settings.AccessToken);

        using var response = await CallAsync(flow, tokens.AccessToken);

        await AssertInvalidTokenAsync(response);
    }

    [DockerFact]
    public async Task Disabled_user_gets_no_data_with_a_valid_token()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid", flow.UserInfoUrl);
        await using (var scope = flow.Api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
            var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
            var user = await users.FindByEmailAsync(flow.Tenant.Tenant.Id, Email, CancellationToken.None);
            user!.Disable();
            await users.SaveChangesAsync(CancellationToken.None);
        }

        using var response = await CallAsync(flow, tokens.AccessToken);

        await AssertInvalidTokenAsync(response);
    }

    [DockerFact]
    public async Task Token_of_another_tenant_is_refused()
    {
        await using var flowA = await SetUpAsync();
        var tenantB = await flowA.Api.AddTenantAsync();
        await flowA.Api.AddWebClientAsync(tenantB);
        await flowA.Api.AddUserAsync(tenantB, Email, Password);
        using var browserB = new BrowserSession(flowA.Api, tenantB.Host);
        using (var login = await browserB.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        await using var flowB = new Flow(flowA.Api, tenantB, browserB, flowA.Api.ClientFor(tenantB.Host));
        var tokensB = await GetTokensAsync(flowB, "openid", flowB.UserInfoUrl);

        using var atA = await CallAsync(flowA, tokensB.AccessToken);
        using var atB = await CallAsync(flowB, tokensB.AccessToken);

        await AssertInvalidTokenAsync(atA);
        Assert.Equal(HttpStatusCode.OK, atB.StatusCode);
    }

    [DockerFact]
    public async Task Token_without_openid_is_insufficient_scope()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "profile", flow.UserInfoUrl);

        using var response = await CallAsync(flow, tokens.AccessToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("Bearer error=\"insufficient_scope\"", response.Headers.WwwAuthenticate.ToString());
    }

    [DockerFact]
    public async Task Client_credentials_cannot_get_a_userinfo_token()
    {
        await using var flow = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials"), new("resource", flow.UserInfoUrl)]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(flow.Tenant.ClientId, flow.Tenant.ClientSecret);

        using var response = await flow.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("""{"error":"invalid_target"}""", await response.Content.ReadAsStringAsync());
    }

    [DockerFact]
    public async Task Missing_token_gets_a_challenge_and_a_token_in_the_query_is_refused()
    {
        await using var flow = await SetUpAsync();
        var tokens = await GetTokensAsync(flow, "openid", flow.UserInfoUrl);

        using var none = await CallAsync(flow, token: null);
        using var basic = await flow.Http.SendAsync(new HttpRequestMessage(HttpMethod.Get, "oauth/v1/userinfo")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Basic", "eDp5") },
        });
        using var inQuery = await CallAsync(flow, token: null, path: "oauth/v1/userinfo?access_token=" + tokens.AccessToken);

        Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);
        // RFC 9449, section 7.1: both schemes work here, so the challenge names both.
        Assert.Equal("Bearer, DPoP algs=\"ES256 RS256\"", none.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, basic.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, inQuery.StatusCode);
        Assert.Equal("""{"error":"invalid_request"}""", await inQuery.Content.ReadAsStringAsync());
    }
}
