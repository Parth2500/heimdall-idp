using System.Net;
using Heimdall.Application.UserInfo;

namespace Heimdall.IntegrationTests.Api;

/// <summary>Cross-origin reads (D23). Each test maps to a row of the CORS table in the threat model.</summary>
[Collection(PostgresGroup.Name)]
public sealed class CorsTests
{
    private const string SpaOrigin = "https://app.example.com";

    private readonly PostgresFixture _postgres;

    public CorsTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task Token_response_names_a_registered_client_origin_and_never_allows_credentials()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);

        using var response = await PostTokenAsync(http, SpaOrigin);

        // The grant itself fails (no valid code). The page can still read the OAuth error.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(SpaOrigin, Single(response, "Access-Control-Allow-Origin"));
        Assert.Contains("Origin", response.Headers.Vary);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [DockerTheory]
    [InlineData("https://evil.example")]
    [InlineData("https://app.example.com.evil.example")]
    [InlineData("http://app.example.com")]
    [InlineData("null")]
    public async Task Unregistered_origin_gets_no_cors_header(string origin)
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);

        using var response = await PostTokenAsync(http, origin);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.Contains("Origin", response.Headers.Vary);
    }

    [DockerFact]
    public async Task Origin_of_another_tenants_client_is_not_allowed()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var other = await api.AddTenantAsync();
        await api.AddWebClientAsync(other);
        using var http = api.ClientFor(tenant.Host);

        using var response = await PostTokenAsync(http, SpaOrigin);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [DockerFact]
    public async Task Userinfo_preflight_allows_the_authorization_and_DPoP_headers()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);

        using var response = await PreflightAsync(http, UserInfoEndpoint.Path, SpaOrigin, "GET", "authorization, dpop");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(SpaOrigin, Single(response, "Access-Control-Allow-Origin"));
        Assert.Equal("GET, POST", Single(response, "Access-Control-Allow-Methods"));
        Assert.Equal("Authorization, DPoP", Single(response, "Access-Control-Allow-Headers"));
        Assert.Equal("600", Single(response, "Access-Control-Max-Age"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [DockerTheory]
    [InlineData("/oauth/v1/userinfo", "PUT", "authorization")]
    [InlineData("/oauth/v1/userinfo", "GET", "authorization, x-custom")]
    [InlineData("/oauth/v1/token", "POST", "content-type")]
    [InlineData("/oauth/v1/token", "DELETE", "")]
    public async Task Preflight_for_a_method_or_header_outside_the_rule_gets_no_cors_header(string path, string method, string requestHeaders)
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);

        using var response = await PreflightAsync(http, path, SpaOrigin, method, requestHeaders);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Methods"));
    }

    [DockerFact]
    public async Task Userinfo_error_exposes_www_authenticate_to_the_page()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoEndpoint.Path.TrimStart('/'));
        request.Headers.Add("Origin", SpaOrigin);

        using var response = await http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(SpaOrigin, Single(response, "Access-Control-Allow-Origin"));
        Assert.Equal("WWW-Authenticate", Single(response, "Access-Control-Expose-Headers"));
    }

    [DockerTheory]
    [InlineData(".well-known/openid-configuration")]
    [InlineData(".well-known/jwks.json")]
    public async Task Discovery_and_jwks_allow_any_origin(string path)
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Origin", "https://anyone.example");

        using var response = await http.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("*", Single(response, "Access-Control-Allow-Origin"));
    }

    [DockerFact]
    public async Task Session_api_gets_no_cors_header_even_for_a_client_origin()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);
        using var request = new HttpRequestMessage(HttpMethod.Get, "session/v1/csrf");
        request.Headers.Add("Origin", SpaOrigin);

        using var response = await http.SendAsync(request);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [DockerFact]
    public async Task Disabled_client_origin_stops_working_after_invalidation()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var client = await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);
        using (var before = await PostTokenAsync(http, SpaOrigin))
        {
            Assert.Equal(SpaOrigin, Single(before, "Access-Control-Allow-Origin"));
        }

        await api.DisableClientAsync(tenant, client.Id);
        using var after = await PostTokenAsync(http, SpaOrigin);

        Assert.False(after.Headers.Contains("Access-Control-Allow-Origin"));
    }

    private static Task<HttpResponseMessage> PostTokenAsync(HttpClient http, string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = "not-a-real-token",
                ["client_id"] = "web-app",
            }),
        };
        request.Headers.Add("Origin", origin);
        return http.SendAsync(request);
    }

    private static Task<HttpResponseMessage> PreflightAsync(HttpClient http, string path, string origin, string method, string requestHeaders)
    {
        var request = new HttpRequestMessage(HttpMethod.Options, path.TrimStart('/'));
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", method);
        if (requestHeaders.Length > 0)
        {
            request.Headers.Add("Access-Control-Request-Headers", requestHeaders);
        }

        return http.SendAsync(request);
    }

    private static string Single(HttpResponseMessage response, string header) =>
        Assert.Single(response.Headers.TryGetValues(header, out var values) ? values : []);
}
