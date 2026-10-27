using System.Net;
using System.Security.Claims;
using Heimdall.IntegrationTests.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Heimdall.IntegrationTests.Interop;

/// <summary>
/// Interop with a certified library (issue #21): the ASP.NET Core OpenID Connect handler, as a relying party on its own
/// test server, signs in through Heimdall and out again. The handler does every protocol step itself: discovery, PAR
/// (it pushes when discovery lists the endpoint), PKCE, state, nonce, the code redemption, the ID token check against
/// the JWKS, and RP-initiated logout.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class AspNetCoreOidcInteropTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string RelyingParty = "https://rp.example.com";

    private readonly PostgresFixture _postgres;

    public AspNetCoreOidcInteropTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    /// <summary>A minimal app with the cookie scheme and the OpenID Connect handler, wired to Heimdall's test server.</summary>
    private static async Task<WebApplication> StartRelyingPartyAsync(HeimdallApiFactory heimdall, TestTenant tenant, PushedAuthorizationBehavior par)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseTestServer();
        builder.Services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.Authority = tenant.Issuer;
                options.ClientId = "web-app";
                options.ResponseType = "code";

                // Heimdall returns the code in the query only. The handler asks for form_post by default.
                options.ResponseMode = "query";
                options.UsePkce = true;
                options.PushedAuthorizationBehavior = par;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("offline_access");
                options.SaveTokens = true;
                options.MapInboundClaims = false;

                // Every call to Heimdall goes to its in-memory test server, with the tenant's host name.
                options.Backchannel = new HttpClient(heimdall.Server.CreateHandler());
            });

        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/protected", (HttpContext context) => context.User.Identity?.IsAuthenticated == true
            ? Results.Text(string.Join(';', context.User.Claims.Select(c => c.Type + "=" + c.Value).Append("issuer=" + context.User.FindFirst("sub")!.Issuer)))
            : Results.Challenge())
            .RequireAuthorization();
        app.MapGet("/refresh-token", async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync();
            return Results.Text(result.Properties?.GetTokenValue("refresh_token") ?? string.Empty);
        })
            .RequireAuthorization();
        app.MapGet("/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/signed-out" });
        });
        app.MapGet("/signed-out", () => Results.Text("signed out"));
        await app.StartAsync();
        return app;
    }

    private sealed record Setup(HeimdallApiFactory Heimdall, TestTenant Tenant, BrowserSession Browser, WebApplication Rp, HttpClient RpClient) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            RpClient.Dispose();
            Browser.Dispose();
            await Rp.DisposeAsync();
            await Heimdall.DisposeAsync();
        }
    }

    private async Task<Setup> SetUpAsync(PushedAuthorizationBehavior par = PushedAuthorizationBehavior.UseIfAvailable)
    {
        var heimdall = new HeimdallApiFactory(_postgres);
        var tenant = await heimdall.AddTenantAsync();
        await heimdall.AddWebClientAsync(
            tenant,
            postLogoutRedirectUris: [RelyingParty + "/signout-callback-oidc"],
            redirectUris: [RelyingParty + "/signin-oidc"]);
        await heimdall.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(heimdall, tenant.Host);
        using (var login = await browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        var rp = await StartRelyingPartyAsync(heimdall, tenant, par);

        // The relying party keeps its own cookies, as a browser keeps them for its origin.
        var rpClient = new HttpClient(new CookieContainerHandler { InnerHandler = rp.GetTestServer().CreateHandler() }) { BaseAddress = new Uri(RelyingParty) };
        return new Setup(heimdall, tenant, browser, rp, rpClient);
    }

    /// <summary>The browser's trip: the app sends it to Heimdall, Heimdall sends it back with a code.</summary>
    private static async Task<HttpResponseMessage> SignInAsync(Setup setup)
    {
        using var challenge = await setup.RpClient.GetAsync("/protected");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var authorize = challenge.Headers.Location!;
        Assert.Equal(setup.Tenant.Issuer + "/oauth/v1/authorize", authorize.GetLeftPart(UriPartial.Path));

        using var atHeimdall = await setup.Browser.SendAsync(HttpMethod.Get, authorize.PathAndQuery.TrimStart('/'));
        Assert.Equal(HttpStatusCode.Found, atHeimdall.StatusCode);
        var callback = atHeimdall.Headers.Location!;
        Assert.Equal(RelyingParty + "/signin-oidc", callback.GetLeftPart(UriPartial.Path));

        // The handler redeems the code over its back channel and checks the ID token.
        using var redeemed = await setup.RpClient.GetAsync(callback.PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, redeemed.StatusCode);
        Assert.Equal("/protected", redeemed.Headers.Location!.OriginalString);
        return await setup.RpClient.GetAsync("/protected");
    }

    [DockerFact]
    public async Task Handler_signs_in_through_par_and_gets_the_users_claims()
    {
        await using var setup = await SetUpAsync();

        using var challenge = await setup.RpClient.GetAsync("/protected");

        // The handler pushed the request: the address carries no authorization parameter, only client_id and
        // request_uri. The handler adds its own telemetry (x-client-SKU, x-client-ver), which Heimdall ignores.
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);
        Assert.Equal(["client_id", "request_uri"], query.Keys.Where(k => !k.StartsWith("x-client-", StringComparison.Ordinal)).Order(StringComparer.Ordinal));
        Assert.StartsWith("urn:ietf:params:oauth:request_uri:", query["request_uri"].ToString(), StringComparison.Ordinal);
    }

    [DockerTheory]
    [InlineData(PushedAuthorizationBehavior.UseIfAvailable)]
    [InlineData(PushedAuthorizationBehavior.Disable)]
    public async Task Handler_signs_in_with_and_without_par(PushedAuthorizationBehavior par)
    {
        await using var setup = await SetUpAsync(par);

        using var page = await SignInAsync(setup);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var claims = (await page.Content.ReadAsStringAsync()).Split(';').Select(c => c.Split('=', 2)).ToDictionary(c => c[0], c => c[1]);
        Assert.Equal(setup.Tenant.Issuer, claims["issuer"]);
        Assert.Matches("^[A-Za-z0-9_-]{22}$", claims["sid"]);
        Assert.True(Guid.TryParse(claims["sub"], out _));

        // SaveTokens keeps the refresh token, because the scope has offline_access.
        Assert.Equal(43, (await setup.RpClient.GetStringAsync("/refresh-token")).Length);
    }

    [DockerFact]
    public async Task Handler_signs_out_of_heimdall_with_its_id_token()
    {
        await using var setup = await SetUpAsync();
        using (await SignInAsync(setup))
        {
        }

        using var logout = await setup.RpClient.GetAsync("/logout");
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        var endSession = logout.Headers.Location!;
        Assert.Equal(setup.Tenant.Issuer + "/oauth/v1/logout", endSession.GetLeftPart(UriPartial.Path));
        Assert.Contains("id_token_hint=", endSession.Query, StringComparison.Ordinal);

        // The hint names this session, so Heimdall ends it at once and returns to the registered URI with state.
        using var atHeimdall = await setup.Browser.SendAsync(HttpMethod.Get, endSession.PathAndQuery.TrimStart('/'));
        Assert.Equal(HttpStatusCode.Found, atHeimdall.StatusCode);
        var back = atHeimdall.Headers.Location!;
        Assert.Equal(RelyingParty + "/signout-callback-oidc", back.GetLeftPart(UriPartial.Path));
        Assert.Contains("state=", back.Query, StringComparison.Ordinal);

        // The handler checks the state and finishes its sign-out.
        using var finished = await setup.RpClient.GetAsync(back.PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, finished.StatusCode);
        Assert.Equal("/signed-out", finished.Headers.Location!.OriginalString);

        using var me = await setup.Browser.MeAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }
}
