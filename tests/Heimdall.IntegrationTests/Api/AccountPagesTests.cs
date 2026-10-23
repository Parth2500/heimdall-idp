using System.Net;
using System.Text.RegularExpressions;

namespace Heimdall.IntegrationTests.Api;

/// <summary>The account pages under /account/ (U2) and their policy (U3).</summary>
[Collection(PostgresGroup.Name)]
public sealed partial class AccountPagesTests
{
    private readonly PostgresFixture _postgres;

    public AccountPagesTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerTheory]
    [InlineData("login")]
    [InlineData("consent")]
    [InlineData("error")]
    [InlineData("signed-out")]
    public async Task Page_gets_a_strict_policy_with_the_nonce_of_its_body(string page)
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync($"account/{page}?request_id=0192d7c3-0000-7000-8000-000000000001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));

        var policy = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));
        var nonce = NonceIn(policy);
        Assert.Contains("default-src 'none'", policy, StringComparison.Ordinal);
        Assert.Contains($"script-src 'self' 'nonce-{nonce}'", policy, StringComparison.Ordinal);
        Assert.Contains($"style-src 'self' 'nonce-{nonce}'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("require-trusted-types-for 'script'", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("unsafe-inline", policy, StringComparison.Ordinal);

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("__HEIMDALL_CSP_NONCE__", body, StringComparison.Ordinal);
        Assert.Contains($"nonce=\"{nonce}\"", body, StringComparison.Ordinal);
        Assert.Contains($"ngCspNonce=\"{nonce}\"", body, StringComparison.Ordinal);
    }

    [DockerFact]
    public async Task Each_response_gets_a_new_nonce()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var first = await http.GetAsync("account/login");
        using var second = await http.GetAsync("account/login");

        var a = NonceIn(Assert.Single(first.Headers.GetValues("Content-Security-Policy")));
        var b = NonceIn(Assert.Single(second.Headers.GetValues("Content-Security-Policy")));
        Assert.NotEqual(a, b);
        Assert.True(a.Length >= 22, "A nonce has at least 128 bits.");
    }

    [DockerFact]
    public async Task Hashed_bundle_is_cached_for_a_year()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync($"account/{AccountFixture.Bundle}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/javascript", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("public, max-age=31536000, immutable", response.Headers.CacheControl?.ToString());
    }

    [DockerFact]
    public async Task Hashed_font_is_served_as_woff2_and_cached_for_a_year()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync($"account/{AccountFixture.Font}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("font/woff2", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("public, max-age=31536000, immutable", response.Headers.CacheControl?.ToString());
    }

    [DockerTheory]
    [InlineData("account/index.html")]
    [InlineData("account/")]
    [InlineData("account/admin")]
    public async Task Index_is_never_served_without_its_nonce_and_unknown_pages_are_404(string path)
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync(path);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [DockerFact]
    public async Task Pages_exist_only_on_a_tenant_origin()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        using var http = api.ClientFor("unknown.example");

        using var response = await http.GetAsync("account/login");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static string NonceIn(string policy) => NoncePattern().Match(policy).Groups[1].Value;

    [GeneratedRegex("'nonce-([A-Za-z0-9_-]+)'")]
    private static partial Regex NoncePattern();
}
