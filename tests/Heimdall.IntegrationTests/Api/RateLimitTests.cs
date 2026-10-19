using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Heimdall.IntegrationTests.Api;

/// <summary>Rate limits (threat model, Limits and lifetimes). Each test sets small limits for one server.</summary>
[Collection(PostgresGroup.Name)]
public sealed class RateLimitTests
{
    private readonly PostgresFixture _postgres;

    public RateLimitTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static WebApplicationFactory<Program> WithLimit(HeimdallApiFactory api, string name, int permits) =>
        api.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration(configuration => configuration.AddInMemoryCollection(
            new Dictionary<string, string?> { [$"Heimdall:RateLimits:{name}:PermitLimit"] = permits.ToString(CultureInfo.InvariantCulture) })));

    private static HttpRequestMessage TokenRequest(TestTenant tenant, string secret)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, secret);
        return request;
    }

    private static async Task AssertRateLimitedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.NotNull(response.Headers.RetryAfter?.Delta);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Equal("""{"error":"temporarily_unavailable"}""", await response.Content.ReadAsStringAsync());
    }

    [DockerFact]
    public async Task Failed_client_authentications_use_up_the_ip_budget_and_then_even_the_right_secret_waits()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await using var host = WithLimit(api, "ClientFailures", 3);
        using var http = host.CreateClient(new() { BaseAddress = new Uri($"https://{tenant.Host}/") });

        for (var i = 0; i < 3; i++)
        {
            using var wrong = await http.SendAsync(TokenRequest(tenant, "wrong-secret"));
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        // Blocked before the secret check: a guesser learns nothing more, and the database does no work.
        using var right = await http.SendAsync(TokenRequest(tenant, tenant.ClientSecret));
        await AssertRateLimitedAsync(right);
    }

    [DockerFact]
    public async Task Successful_requests_do_not_use_the_failure_budget()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await using var host = WithLimit(api, "ClientFailures", 2);
        using var http = host.CreateClient(new() { BaseAddress = new Uri($"https://{tenant.Host}/") });

        // A backend that gets many tokens from one address is never blocked by the failure budget.
        for (var i = 0; i < 6; i++)
        {
            using var ok = await http.SendAsync(TokenRequest(tenant, tenant.ClientSecret));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
    }

    [DockerFact]
    public async Task Issuance_budget_counts_only_the_clients_own_successes()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await using var host = WithLimit(api, "ClientIssuance", 2);
        using var http = host.CreateClient(new() { BaseAddress = new Uri($"https://{tenant.Host}/") });

        // Wrong secrets with the victim's client_id: they do not touch its issuance budget.
        for (var i = 0; i < 5; i++)
        {
            using var wrong = await http.SendAsync(TokenRequest(tenant, "wrong-secret"));
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        using var first = await http.SendAsync(TokenRequest(tenant, tenant.ClientSecret));
        using var second = await http.SendAsync(TokenRequest(tenant, tenant.ClientSecret));
        using var third = await http.SendAsync(TokenRequest(tenant, tenant.ClientSecret));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        await AssertRateLimitedAsync(third);
    }

    [DockerFact]
    public async Task Sign_in_attempts_are_limited_for_each_address()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddUserAsync(tenant, "alice@example.com", "correct horse battery staple");
        await using var host = WithLimit(api, "Login", 2);
        using var browser = new BrowserSession(host, tenant.Host);

        using var first = await browser.LoginAsync("alice@example.com", "wrong password value");
        using var second = await browser.LoginAsync("alice@example.com", "wrong password value");
        using var third = await browser.LoginAsync("alice@example.com", "correct horse battery staple");

        Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
        await AssertRateLimitedAsync(third);
    }

    [DockerFact]
    public async Task Authorize_requests_are_limited_for_each_address()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await using var host = WithLimit(api, "Authorize", 2);
        using var http = host.CreateClient(new() { BaseAddress = new Uri($"https://{tenant.Host}/"), AllowAutoRedirect = false });

        using var first = await http.GetAsync("oauth/v1/authorize?client_id=unknown");
        using var second = await http.GetAsync("oauth/v1/authorize?client_id=unknown");
        using var third = await http.GetAsync("oauth/v1/authorize?client_id=unknown");

        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        await AssertRateLimitedAsync(third);
    }

    [Theory]
    [InlineData("203.0.113.9", "203.0.113.9")]
    [InlineData("::ffff:203.0.113.9", "203.0.113.9")]
    [InlineData("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    public void Ipv6_addresses_share_a_budget_for_each_64_network(string address, string key)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(address);

        Assert.Equal(key, Heimdall.Api.Hosting.RateLimits.IpKey(context));
    }
}
