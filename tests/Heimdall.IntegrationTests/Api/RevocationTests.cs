using System.Net;
using System.Text.Json;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// <c>POST /oauth/v1/revoke</c> (RFC 7009). Each test maps to a row of the /revoke table in the threat model.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class RevocationTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public RevocationTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, HttpClient Http, string RefreshToken, string AccessToken) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    /// <summary>Signs in, gets a code with offline_access, and redeems it.</summary>
    private async Task<Flow> SetUpAsync()
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        await api.AddWebClientAsync(tenant, clientId: "other-app");
        await api.AddUserAsync(tenant, Email, Password);

        using var browser = new BrowserSession(api, tenant.Host);
        using (var login = await browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        string code;
        using (var authorize = await browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        })))
        {
            var location = authorize.Headers.Location!.OriginalString;
            code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
        }

        var http = api.ClientFor(tenant.Host);
        using var redeemed = await http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", "web-app"),
        ]));
        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        var body = JsonDocument.Parse(await redeemed.Content.ReadAsStringAsync()).RootElement;
        return new Flow(api, tenant, http, body.GetProperty("refresh_token").GetString()!, body.GetProperty("access_token").GetString()!);
    }

    private static Task<HttpResponseMessage> RevokeAsync(Flow flow, string token, string clientId = "web-app") =>
        flow.Http.PostAsync("oauth/v1/revoke", new FormUrlEncodedContent([new("token", token), new("client_id", clientId)]));

    private static Task<HttpResponseMessage> RefreshAsync(Flow flow, string refreshToken) =>
        flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
            new("client_id", "web-app"),
        ]));

    private static async Task<TokenFamily> FamilyAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.AsNoTracking().SingleAsync();
    }

    private static async Task<List<AuditEvent>> AuditAsync(Flow flow, string type)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking()
            .Where(e => e.TenantId == flow.Tenant.Tenant.Id && e.Type == type)
            .ToListAsync();
    }

    [DockerFact]
    public async Task Revoking_a_refresh_token_ends_its_family()
    {
        await using var flow = await SetUpAsync();

        using var response = await RevokeAsync(flow, flow.RefreshToken);
        using var refresh = await RefreshAsync(flow, flow.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        Assert.Equal(FamilyRevocationReason.UserLogout, (await FamilyAsync(flow)).RevocationReason);
        Assert.Single(await AuditAsync(flow, AuditEventTypes.FamilyRevoked));
    }

    [DockerFact]
    public async Task An_old_token_of_the_family_also_revokes_the_newest_token()
    {
        await using var flow = await SetUpAsync();
        using var rotated = await RefreshAsync(flow, flow.RefreshToken);
        var newest = JsonDocument.Parse(await rotated.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;

        using var response = await RevokeAsync(flow, flow.RefreshToken);
        using var refresh = await RefreshAsync(flow, newest);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);

        // Revocation is not reuse: the reason stays user_logout, and no reuse alert exists.
        Assert.Equal(FamilyRevocationReason.UserLogout, (await FamilyAsync(flow)).RevocationReason);
        Assert.Empty(await AuditAsync(flow, AuditEventTypes.RefreshReuseDetected));
    }

    [DockerFact]
    public async Task Another_client_cannot_revoke_the_token_and_gets_the_same_200()
    {
        await using var flow = await SetUpAsync();

        using var response = await RevokeAsync(flow, flow.RefreshToken, clientId: "other-app");
        using var refresh = await RefreshAsync(flow, flow.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        Assert.Null((await FamilyAsync(flow)).RevokedAt);
        Assert.Single(await AuditAsync(flow, AuditEventTypes.RevocationRefused));
    }

    [DockerFact]
    public async Task Unknown_tokens_and_access_tokens_get_200_and_change_nothing()
    {
        await using var flow = await SetUpAsync();

        using var unknown = await RevokeAsync(flow, new string('r', 43));
        using var accessToken = await RevokeAsync(flow, flow.AccessToken);

        Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.OK, accessToken.StatusCode);
        Assert.Null((await FamilyAsync(flow)).RevokedAt);
    }

    [DockerFact]
    public async Task A_second_revocation_is_200_and_keeps_the_first_record()
    {
        await using var flow = await SetUpAsync();

        using var first = await RevokeAsync(flow, flow.RefreshToken);
        var revokedAt = (await FamilyAsync(flow)).RevokedAt;
        flow.Api.Time.Advance(TimeSpan.FromMinutes(1));
        using var second = await RevokeAsync(flow, flow.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(revokedAt, (await FamilyAsync(flow)).RevokedAt);
        Assert.Single(await AuditAsync(flow, AuditEventTypes.FamilyRevoked));
    }

    [DockerFact]
    public async Task A_wrong_client_secret_is_invalid_client_and_is_audited()
    {
        await using var flow = await SetUpAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/revoke")
        {
            Content = new FormUrlEncodedContent([new("token", flow.RefreshToken)]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(flow.Tenant.ClientId, "wrong-secret");

        using var response = await flow.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("""{"error":"invalid_client"}""", await response.Content.ReadAsStringAsync());
        Assert.Single(await AuditAsync(flow, AuditEventTypes.RevocationRefused));
        Assert.Null((await FamilyAsync(flow)).RevokedAt);
    }

    [DockerFact]
    public async Task Malformed_requests_get_invalid_request()
    {
        await using var flow = await SetUpAsync();

        using var noToken = await flow.Http.PostAsync("oauth/v1/revoke", new FormUrlEncodedContent([new("client_id", "web-app")]));
        using var inQuery = await flow.Http.PostAsync(
            "oauth/v1/revoke?token=" + flow.RefreshToken,
            new FormUrlEncodedContent([new("client_id", "web-app")]));
        using var repeated = await flow.Http.PostAsync("oauth/v1/revoke", new FormUrlEncodedContent(
            [new("token", flow.RefreshToken), new("token", "x"), new("client_id", "web-app")]));

        foreach (var response in new[] { noToken, inQuery, repeated })
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("""{"error":"invalid_request"}""", await response.Content.ReadAsStringAsync());
        }

        Assert.Null((await FamilyAsync(flow)).RevokedAt);
    }
}
