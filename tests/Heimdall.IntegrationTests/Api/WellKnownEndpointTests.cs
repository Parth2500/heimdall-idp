using System.Net;
using System.Text.Json;
using Heimdall.Application.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>Discovery, JWKS, and the middleware that runs before every endpoint.</summary>
[Collection(PostgresGroup.Name)]
public sealed class WellKnownEndpointTests
{
    private readonly PostgresFixture _postgres;

    public WellKnownEndpointTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task Discovery_lists_what_exists_today()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync(".well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;
        Assert.Equal(tenant.Issuer, root.GetProperty("issuer").GetString());
        Assert.Equal(tenant.Issuer + "/oauth/v1/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal(tenant.Issuer + "/.well-known/jwks.json", root.GetProperty("jwks_uri").GetString());
        Assert.Equal(tenant.Issuer + "/oauth/v1/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal(["authorization_code", "client_credentials"], root.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["S256"], root.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.True(root.GetProperty("authorization_response_iss_parameter_supported").GetBoolean());

        // Not built yet, so not listed.
        Assert.False(root.TryGetProperty("userinfo_endpoint", out _));
        Assert.True(response.Headers.CacheControl?.Public);
        Assert.Equal(api.KeyOptions.JwksCacheLifetime, response.Headers.CacheControl?.MaxAge);
    }

    [DockerFact]
    public async Task Each_tenant_has_its_own_issuer()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenantA = await api.AddTenantAsync();
        var tenantB = await api.AddTenantAsync();

        var issuerA = await IssuerAsync(api, tenantA);
        var issuerB = await IssuerAsync(api, tenantB);

        Assert.Equal(tenantA.Issuer, issuerA);
        Assert.Equal(tenantB.Issuer, issuerB);
        Assert.NotEqual(issuerA, issuerB);

        static async Task<string?> IssuerAsync(HeimdallApiFactory api, TestTenant tenant)
        {
            using var http = api.ClientFor(tenant.Host);
            using var document = JsonDocument.Parse(await http.GetStringAsync(".well-known/openid-configuration"));
            return document.RootElement.GetProperty("issuer").GetString();
        }
    }

    [DockerFact]
    public async Task Jwks_publishes_pending_and_active_keys_with_public_members_only()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var other = await api.AddTenantAsync();

        // A second, pending key: it is in the JWKS before it can sign.
        await using (var scope = api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
            await scope.ServiceProvider.GetRequiredService<SigningKeyService>().CreateKeyAsync(tenant.Tenant.Id, "test", CancellationToken.None);
        }

        using var http = api.ClientFor(tenant.Host);
        using var response = await http.GetAsync(".well-known/jwks.json");
        using var otherHttp = api.ClientFor(other.Host);
        using var otherJwks = JsonDocument.Parse(await otherHttp.GetStringAsync(".well-known/jwks.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var jwks = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var keys = jwks.RootElement.GetProperty("keys").EnumerateArray().ToList();
        Assert.Equal(2, keys.Count);
        foreach (var key in keys)
        {
            Assert.Equal(["alg", "e", "kid", "kty", "n", "use"], key.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        }

        var kids = keys.Select(k => k.GetProperty("kid").GetString()).ToHashSet();
        var otherKid = Assert.Single(otherJwks.RootElement.GetProperty("keys").EnumerateArray()).GetProperty("kid").GetString();
        Assert.DoesNotContain(otherKid, kids);
    }

    [DockerFact]
    public async Task Jwks_returns_304_for_a_matching_ETag()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var first = await http.GetAsync(".well-known/jwks.json");
        var etag = first.Headers.ETag;
        Assert.NotNull(etag);

        using var request = new HttpRequestMessage(HttpMethod.Get, ".well-known/jwks.json");
        request.Headers.IfNoneMatch.Add(etag);
        using var second = await http.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
        Assert.Empty(await second.Content.ReadAsByteArrayAsync());
        Assert.Equal(etag, second.Headers.ETag);
    }

    [DockerFact]
    public async Task Unknown_host_and_unknown_path_get_the_same_empty_404()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var unknownHost = api.ClientFor("not-a-tenant.test");
        using var knownHost = api.ClientFor(tenant.Host);

        using var hostMiss = await unknownHost.GetAsync(".well-known/openid-configuration");
        using var pathMiss = await knownHost.GetAsync("no-such-path");

        Assert.Equal(HttpStatusCode.NotFound, hostMiss.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, pathMiss.StatusCode);
        Assert.Empty(await hostMiss.Content.ReadAsByteArrayAsync());
        Assert.Empty(await pathMiss.Content.ReadAsByteArrayAsync());
        Assert.Equal(hostMiss.Content.Headers.ContentType, pathMiss.Content.Headers.ContentType);
    }

    [DockerFact]
    public async Task Plain_http_is_refused_not_redirected()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host, scheme: "http");

        using var response = await http.PostAsync("oauth/v1/token", new FormUrlEncodedContent([new("grant_type", "client_credentials")]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Contains("invalid_request", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [DockerFact]
    public async Task Safe_correlation_id_is_kept_and_an_unsafe_one_is_replaced()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var safe = new HttpRequestMessage(HttpMethod.Get, ".well-known/jwks.json");
        safe.Headers.Add("X-Correlation-ID", "client-req-42");
        using var unsafeRequest = new HttpRequestMessage(HttpMethod.Get, ".well-known/jwks.json");
        unsafeRequest.Headers.TryAddWithoutValidation("X-Correlation-ID", "fake\" level=critical " + new string('x', 80));

        using var safeResponse = await http.SendAsync(safe);
        using var unsafeResponse = await http.SendAsync(unsafeRequest);

        Assert.Equal("client-req-42", Assert.Single(safeResponse.Headers.GetValues("X-Correlation-ID")));
        var replaced = Assert.Single(unsafeResponse.Headers.GetValues("X-Correlation-ID"));
        Assert.Matches("^[0-9a-f]{32}$", replaced);
    }
}
