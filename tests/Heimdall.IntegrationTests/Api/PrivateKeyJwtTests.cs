using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Purge;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// <c>private_key_jwt</c> client authentication (#67, D45 to D49) at <c>/token</c>, <c>/introspect</c>, and
/// <c>/revoke</c>, with a real ES256 key and the real replay table.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class PrivateKeyJwtTests : IDisposable
{
    private const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private readonly PostgresFixture _postgres;
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public PrivateKeyJwtTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    public void Dispose() => _key.Dispose();

    private sealed record Setup(HeimdallApiFactory Api, TestTenant Tenant, HttpClient Http) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    private async Task<Setup> SetUpAsync()
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var p = _key.ExportParameters(includePrivateParameters: false);
        var jwks = new JsonObject
        {
            ["keys"] = new JsonArray(new JsonObject
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["kid"] = "key-1",
                ["x"] = Base64Url.EncodeToString(p.Q.X!),
                ["y"] = Base64Url.EncodeToString(p.Q.Y!),
            }),
        };
        await api.UsePrivateKeyJwtAsync(tenant, jwks.ToJsonString());
        return new Setup(api, tenant, api.ClientFor(tenant.Host));
    }

    private string Assertion(Setup setup, string? aud = null, string? jti = null)
    {
        static string Encode(JsonNode node) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(node.ToJsonString()));

        var now = setup.Api.Time.GetUtcNow();
        var header = new JsonObject { ["alg"] = "ES256", ["kid"] = "key-1", ["typ"] = "client-authentication+jwt" };
        var payload = new JsonObject
        {
            ["iss"] = setup.Tenant.ClientId,
            ["sub"] = setup.Tenant.ClientId,
            ["aud"] = aud ?? setup.Tenant.Issuer,
            ["jti"] = jti ?? Guid.NewGuid().ToString(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds(),
        };
        var input = Encode(header) + "." + Encode(payload);
        var signature = _key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return input + "." + Base64Url.EncodeToString(signature);
    }

    private static Task<HttpResponseMessage> PostAsync(Setup setup, string path, string? assertion, params (string Name, string Value)[] form)
    {
        var fields = form.Select(f => new KeyValuePair<string, string>(f.Name, f.Value)).ToList();
        if (assertion is not null)
        {
            fields.Add(new("client_assertion_type", JwtBearer));
            fields.Add(new("client_assertion", assertion));
        }

        return setup.Http.PostAsync(path, new FormUrlEncodedContent(fields));
    }

    private static async Task<string> ErrorOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString()!;

    [DockerFact]
    public async Task Client_credentials_with_an_assertion_issues_a_token()
    {
        await using var setup = await SetUpAsync();

        using var response = await PostAsync(setup, "oauth/v1/token", Assertion(setup), ("grant_type", "client_credentials"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
    }

    [DockerFact]
    public async Task Same_assertion_twice_is_invalid_client()
    {
        await using var setup = await SetUpAsync();
        var assertion = Assertion(setup);

        using var first = await PostAsync(setup, "oauth/v1/token", assertion, ("grant_type", "client_credentials"));
        using var replay = await PostAsync(setup, "oauth/v1/token", assertion, ("grant_type", "client_credentials"));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal("invalid_client", await ErrorOf(replay));
    }

    [DockerFact]
    public async Task Concurrent_uses_of_one_assertion_issue_one_token()
    {
        // D49: the unique key of client_assertions decides. Two servers that race get one success.
        await using var setup = await SetUpAsync();
        await using var other = setup.Api.WithWebHostBuilder(_ => { });
        using var otherHttp = other.CreateClient(new() { BaseAddress = new Uri($"https://{setup.Tenant.Host}/") });
        var assertion = Assertion(setup);
        FormUrlEncodedContent Form() => new([
            new("grant_type", "client_credentials"),
            new("client_assertion_type", JwtBearer),
            new("client_assertion", assertion),
        ]);

        var responses = await Task.WhenAll(setup.Http.PostAsync("oauth/v1/token", Form()), otherHttp.PostAsync("oauth/v1/token", Form()));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Unauthorized);
    }

    [DockerFact]
    public async Task Assertion_for_the_token_endpoint_url_is_refused()
    {
        // D48: aud is the issuer only (draft-ietf-oauth-rfc7523bis).
        await using var setup = await SetUpAsync();

        using var response = await PostAsync(
            setup, "oauth/v1/token", Assertion(setup, aud: setup.Tenant.Issuer + "/oauth/v1/token"), ("grant_type", "client_credentials"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [DockerFact]
    public async Task Old_secret_of_a_private_key_jwt_client_is_refused()
    {
        // D47: one method for each client.
        await using var setup = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(setup.Tenant.ClientId, setup.Tenant.ClientSecret);

        using var response = await setup.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ErrorOf(response));
    }

    [DockerFact]
    public async Task Basic_header_and_assertion_together_are_invalid_request()
    {
        await using var setup = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([
                new("grant_type", "client_credentials"),
                new("client_assertion_type", JwtBearer),
                new("client_assertion", Assertion(setup)),
            ]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(setup.Tenant.ClientId, setup.Tenant.ClientSecret);

        using var response = await setup.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await ErrorOf(response));
    }

    [DockerFact]
    public async Task Introspection_and_revocation_accept_an_assertion()
    {
        await using var setup = await SetUpAsync();
        using var issued = await PostAsync(setup, "oauth/v1/token", Assertion(setup), ("grant_type", "client_credentials"));
        var token = JsonDocument.Parse(await issued.Content.ReadAsStringAsync()).RootElement.GetProperty("access_token").GetString()!;

        using var introspect = await PostAsync(setup, "oauth/v1/introspect", Assertion(setup), ("token", token));
        using var revoke = await PostAsync(setup, "oauth/v1/revoke", Assertion(setup), ("token", "not-a-token-of-anyone"));

        Assert.Equal(HttpStatusCode.OK, introspect.StatusCode);
        Assert.True(JsonDocument.Parse(await introspect.Content.ReadAsStringAsync()).RootElement.GetProperty("active").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
    }

    [DockerFact]
    public async Task Purge_deletes_the_replay_row_after_exp()
    {
        await using var setup = await SetUpAsync();
        using var issued = await PostAsync(setup, "oauth/v1/token", Assertion(setup), ("grant_type", "client_credentials"));

        Assert.Equal(1, await CountAsync(setup));
        await PurgeAsync(setup);
        Assert.Equal(1, await CountAsync(setup));

        setup.Api.Time.Advance(TimeSpan.FromMinutes(4));
        var result = await PurgeAsync(setup);

        // The purge runs for every tenant, so other tests' expired rows can count too.
        Assert.True(result.ClientAssertions >= 1);
        Assert.Equal(0, await CountAsync(setup));
    }

    private static async Task<int> CountAsync(Setup setup)
    {
        await using var scope = setup.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(setup.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().ClientAssertions.CountAsync();
    }

    private static async Task<PurgeResult> PurgeAsync(Setup setup)
    {
        await using var scope = setup.Api.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<DataPurger>().RunOnceAsync(CancellationToken.None);
    }
}
