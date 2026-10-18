using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// <c>POST /oauth/v1/token</c> over HTTP, through the real middleware. Each rule maps to a row of the /token table in
/// docs/threat-model.md.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class TokenEndpointTests
{
    private const string Audience = "https://api.example.com";

    private readonly PostgresFixture _postgres;

    public TokenEndpointTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static HttpRequestMessage TokenRequest(
        TestTenant tenant,
        IEnumerable<KeyValuePair<string, string>>? form = null,
        string? secret = null,
        string path = "oauth/v1/token")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent(form ?? [new("grant_type", "client_credentials")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, secret ?? tenant.ClientSecret);
        return request;
    }

    private static async Task<string?> ErrorOf(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        // D5: the body has the error code and nothing else.
        Assert.Equal(["error"], json.RootElement.EnumerateObject().Select(p => p.Name));
        return json.RootElement.GetProperty("error").GetString();
    }

    private static void AssertNoStore(HttpResponseMessage response)
    {
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Contains("no-cache", response.Headers.Pragma.Select(p => p.Name));
    }

    [DockerFact]
    public async Task Issued_token_verifies_against_the_served_JWKS()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.SendAsync(TokenRequest(tenant));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertNoStore(response);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Bearer", body.RootElement.GetProperty("token_type").GetString());
        Assert.Equal(300, body.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal("invoices.read", body.RootElement.GetProperty("scope").GetString());

        // A resource server's view: keys from the JWKS endpoint, checked by an independent library.
        var jwks = new JsonWebKeySet(await http.GetStringAsync(".well-known/jwks.json"));
        var token = body.RootElement.GetProperty("access_token").GetString();
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = tenant.Issuer,
            ValidAudience = Audience,
            ValidAlgorithms = ["RS256"],
            ValidTypes = ["at+jwt"],
            IssuerSigningKeys = jwks.GetSigningKeys(),
            // The token's iat and exp come from the fake clock, which started at the real time.
            LifetimeValidator = (_, _, _, _) => true,
        });

        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal(tenant.ClientId, ((JsonWebToken)result.SecurityToken).Subject);
    }

    [DockerFact]
    public async Task Wrong_secret_gets_401_with_a_Basic_challenge_and_no_reason()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.SendAsync(TokenRequest(tenant, secret: "wrong"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Basic", Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        AssertNoStore(response);
        Assert.Equal("invalid_client", await ErrorOf(response));
    }

    [DockerFact]
    public async Task Rejection_is_audited_with_the_response_correlation_id()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.SendAsync(TokenRequest(tenant, secret: "wrong"));
        var correlationId = Assert.Single(response.Headers.GetValues("X-Correlation-ID"));

        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var audit = await db.AuditEvents.AsNoTracking().SingleAsync(e => e.CorrelationId == correlationId);
        Assert.Equal(AuditEventTypes.TokenRejected, audit.Type);
        Assert.Equal(tenant.Tenant.Id, audit.TenantId);
        Assert.Equal("wrong secret", audit.Data["reason"]);
    }

    [DockerFact]
    public async Task Client_of_another_tenant_is_unknown_here()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenantA = await api.AddTenantAsync(clientSecret: "secret-only-tenant-A-has");
        var tenantB = await api.AddTenantAsync();
        using var http = api.ClientFor(tenantB.Host);

        // Both tenants have a client "billing-service". Tenant A's valid credentials, sent to tenant B's host.
        using var response = await http.SendAsync(TokenRequest(tenantA));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ErrorOf(response));
    }

    [DockerFact]
    public async Task Basic_credentials_are_form_decoded()
    {
        // RFC 6749, section 2.3.1: a secret may hold a colon, a plus, or a percent sign.
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync(clientSecret: "p@ss:w+rd%20 ok");
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.SendAsync(TokenRequest(tenant));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    public static TheoryData<string, string> MalformedRequests => new()
    {
        { "query", "invalid_request" },
        { "json", "invalid_request" },
        { "repeated", "invalid_request" },
        { "secret-in-body", "invalid_request" },
        { "no-grant-type", "invalid_request" },
        { "client-id-mismatch", "invalid_request" },
        { "too-large", "invalid_request" },
        { "unsupported-grant", "unsupported_grant_type" },
    };

    [DockerTheory]
    [MemberData(nameof(MalformedRequests))]
    public async Task Malformed_request_is_refused_before_the_grant(string kind, string expectedError)
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var request = kind switch
        {
            "query" => TokenRequest(tenant, path: "oauth/v1/token?client_secret=leak"),
            "repeated" => TokenRequest(tenant, [new("grant_type", "client_credentials"), new("scope", "a"), new("scope", "b")]),
            "secret-in-body" => TokenRequest(tenant, [new("grant_type", "client_credentials"), new("client_secret", "x")]),
            "no-grant-type" => TokenRequest(tenant, [new("scope", "invoices.read")]),
            "client-id-mismatch" => TokenRequest(tenant, [new("grant_type", "client_credentials"), new("client_id", "other")]),
            "too-large" => TokenRequest(tenant, [new("grant_type", "client_credentials"), new("scope", new string('a', 20_000))]),
            "unsupported-grant" => TokenRequest(tenant, [new("grant_type", "password")]),
            _ => TokenRequest(tenant),
        };
        if (kind == "json")
        {
            request.Content = new StringContent("""{"grant_type":"client_credentials"}""", Encoding.UTF8, "application/json");
        }

        using var response = await http.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertNoStore(response);
        Assert.Equal(expectedError, await ErrorOf(response));

        // Refused before the grant: the grant audits every rejection it sees, and it saw none.
        var correlationId = Assert.Single(response.Headers.GetValues("X-Correlation-ID"));
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        Assert.False(await db.AuditEvents.AnyAsync(e => e.CorrelationId == correlationId));
    }

    [DockerFact]
    public async Task Other_authorization_scheme_is_invalid_client()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);
        using var request = TokenRequest(tenant);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "abc");

        using var response = await http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", await ErrorOf(response));
    }
}
