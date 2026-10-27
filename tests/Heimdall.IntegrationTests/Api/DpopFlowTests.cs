using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// DPoP at /token end to end, with real ES256 proofs that a client signs (D24 to D26). The unit tests cover each
/// rule; these tests prove that the HTTP layer, the replay table and the rotation statement work together.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class DpopFlowTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public DpopFlowTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    /// <summary>A client's DPoP key pair. It signs proofs as RFC 9449, section 4.2 describes.</summary>
    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, HttpClient Http, string Code) : IAsyncDisposable
    {
        public string TokenUrl => Tenant.Issuer + "/oauth/v1/token";

        public string UserInfoUrl => Tenant.Issuer + "/oauth/v1/userinfo";

        public DateTimeOffset Now => Api.Time.GetUtcNow();

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    /// <summary>Signs in and gets a code with offline_access for a public client.</summary>
    private async Task<Flow> SetUpAsync(bool requireDpop = false, string? dpopJkt = null)
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant, requireDpop: requireDpop);
        await api.AddUserAsync(tenant, Email, Password);

        using var browser = new BrowserSession(api, tenant.Host);
        using (var login = await browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        using var authorize = await browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid offline_access",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
            ["dpop_jkt"] = dpopJkt,
        }));
        var location = authorize.Headers.Location!.OriginalString;
        var code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
        return new Flow(api, tenant, api.ClientFor(tenant.Host), code);
    }

    private static Task<HttpResponseMessage> RedeemAsync(Flow flow, string? proof, string? resource = null) =>
        PostTokenAsync(flow, proof,
        [
            new("grant_type", "authorization_code"),
            new("code", flow.Code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", "web-app"),
            .. resource is null ? Array.Empty<KeyValuePair<string, string>>() : [new("resource", resource)],
        ]);

    private static Task<HttpResponseMessage> RefreshAsync(Flow flow, string refreshToken, string? proof) =>
        PostTokenAsync(flow, proof,
        [
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
            new("client_id", "web-app"),
        ]);

    private static Task<HttpResponseMessage> PostTokenAsync(Flow flow, string? proof, KeyValuePair<string, string>[] form)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token") { Content = new FormUrlEncodedContent(form) };
        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        return flow.Http.SendAsync(request);
    }

    private static async Task<JsonElement> OkBodyAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    }

    private static async Task AssertErrorAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal($$"""{"error":"{{error}}"}""", await response.Content.ReadAsStringAsync());
    }

    private static JsonElement AccessTokenClaims(JsonElement body)
    {
        var payload = body.GetProperty("access_token").GetString()!.Split('.')[1];
        return JsonDocument.Parse(Base64Url.DecodeFromChars(payload)).RootElement;
    }

    private static async Task<DateTimeOffset?> FamilyRevokedAtAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return (await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.AsNoTracking().SingleAsync()).RevokedAt;
    }

    [DockerFact]
    public async Task A_proof_at_redemption_binds_the_access_token_to_the_key()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();

        using var response = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now));

        var body = await OkBodyAsync(response);
        Assert.Equal("DPoP", body.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, AccessTokenClaims(body).GetProperty("cnf").GetProperty("jkt").GetString());
    }

    [DockerFact]
    public async Task Without_a_proof_the_token_stays_a_bearer_token()
    {
        await using var flow = await SetUpAsync();

        using var response = await RedeemAsync(flow, proof: null);

        var body = await OkBodyAsync(response);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.False(AccessTokenClaims(body).TryGetProperty("cnf", out _));
    }

    [DockerFact]
    public async Task A_bound_refresh_token_needs_a_proof_from_the_same_key_and_a_thief_cannot_burn_it()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();
        using var thiefKey = new ClientKey();
        using var redeemed = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now));
        var refreshToken = (await OkBodyAsync(redeemed)).GetProperty("refresh_token").GetString()!;

        // The thief holds the refresh token, but not the private key.
        using var noProof = await RefreshAsync(flow, refreshToken, proof: null);
        using var otherKey = await RefreshAsync(flow, refreshToken, thiefKey.Proof(flow.TokenUrl, flow.Now));

        await AssertErrorAsync(noProof, "invalid_dpop_proof");
        await AssertErrorAsync(otherKey, "invalid_grant");
        Assert.Null(await FamilyRevokedAtAsync(flow));

        // The real client still rotates, because the failed attempts did not use the token.
        using var legit = await RefreshAsync(flow, refreshToken, key.Proof(flow.TokenUrl, flow.Now));
        var body = await OkBodyAsync(legit);
        Assert.Equal("DPoP", body.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, AccessTokenClaims(body).GetProperty("cnf").GetProperty("jkt").GetString());
    }

    [DockerFact]
    public async Task A_proof_works_once()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();
        using var redeemed = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now));
        var refreshToken = (await OkBodyAsync(redeemed)).GetProperty("refresh_token").GetString()!;
        var proof = key.Proof(flow.TokenUrl, flow.Now);

        using var first = await RefreshAsync(flow, refreshToken, proof);
        var next = (await OkBodyAsync(first)).GetProperty("refresh_token").GetString()!;
        using var replay = await RefreshAsync(flow, next, proof);

        await AssertErrorAsync(replay, "invalid_dpop_proof");
    }

    [DockerFact]
    public async Task A_proof_for_another_url_or_an_old_proof_is_refused()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();

        using var wrongUrl = await RedeemAsync(flow, key.Proof("https://evil.example/oauth/v1/token", flow.Now));
        using var tooOld = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now.AddMinutes(-5)));

        await AssertErrorAsync(wrongUrl, "invalid_dpop_proof");
        await AssertErrorAsync(tooOld, "invalid_dpop_proof");
    }

    [DockerFact]
    public async Task A_client_that_requires_DPoP_gets_no_token_without_a_proof()
    {
        await using var flow = await SetUpAsync(requireDpop: true);
        using var key = new ClientKey();

        using var refused = await RedeemAsync(flow, proof: null);
        using var bound = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now));

        await AssertErrorAsync(refused, "invalid_dpop_proof");
        Assert.Equal("DPoP", (await OkBodyAsync(bound)).GetProperty("token_type").GetString());
    }

    [DockerFact]
    public async Task Two_DPoP_headers_are_refused()
    {
        await using var flow = await SetUpAsync();
        using var key = new ClientKey();
        var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("code", flow.Code),
                new("code_verifier", Verifier),
                new("redirect_uri", Callback),
                new("client_id", "web-app"),
            ]),
        };
        request.Headers.TryAddWithoutValidation("DPoP", [key.Proof(flow.TokenUrl, flow.Now), key.Proof(flow.TokenUrl, flow.Now)]);

        using var response = await flow.Http.SendAsync(request);

        await AssertErrorAsync(response, "invalid_dpop_proof");
    }

    [DockerFact]
    public async Task A_code_bound_by_dpop_jkt_redeems_only_with_that_key_and_a_thief_cannot_burn_it()
    {
        using var key = new ClientKey();
        using var thiefKey = new ClientKey();
        await using var flow = await SetUpAsync(dpopJkt: key.Thumbprint);

        // The thief holds the code, but not the private key.
        using var noProof = await RedeemAsync(flow, proof: null);
        using var otherKey = await RedeemAsync(flow, thiefKey.Proof(flow.TokenUrl, flow.Now));
        await AssertErrorAsync(noProof, "invalid_dpop_proof");
        await AssertErrorAsync(otherKey, "invalid_grant");

        // The failed attempts did not use the code, so the real client still redeems it.
        using var legit = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now));
        var body = await OkBodyAsync(legit);
        Assert.Equal(key.Thumbprint, AccessTokenClaims(body).GetProperty("cnf").GetProperty("jkt").GetString());
    }

    [DockerFact]
    public async Task A_malformed_dpop_jkt_goes_back_to_the_client_as_invalid_request()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync(QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
            ["dpop_jkt"] = "not-a-thumbprint",
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.OriginalString;
        Assert.StartsWith(Callback + "?", location, StringComparison.Ordinal);
        Assert.Equal("invalid_request", QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["error"].ToString());
    }

    // D28 and RFC 9449, section 7: /userinfo with a bound access token.

    private sealed record UserInfoCall(Flow Flow, ClientKey Key, string AccessToken) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Key.Dispose();
            await Flow.DisposeAsync();
        }
    }

    private async Task<UserInfoCall> BoundUserInfoTokenAsync()
    {
        var flow = await SetUpAsync();
        var key = new ClientKey();
        using var redeemed = await RedeemAsync(flow, key.Proof(flow.TokenUrl, flow.Now), resource: flow.UserInfoUrl);
        var accessToken = (await OkBodyAsync(redeemed)).GetProperty("access_token").GetString()!;
        return new UserInfoCall(flow, key, accessToken);
    }

    private static Task<HttpResponseMessage> UserInfoAsync(Flow flow, string? authorization, params string[] proofs)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "oauth/v1/userinfo");
        if (authorization is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        if (proofs.Length > 0)
        {
            request.Headers.TryAddWithoutValidation("DPoP", proofs);
        }

        return flow.Http.SendAsync(request);
    }

    private static void AssertChallenge(HttpResponseMessage response, string challenge)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(challenge, string.Join(", ", response.Headers.WwwAuthenticate.Select(h => h.ToString())));
    }

    [DockerFact]
    public async Task A_bound_token_reads_userinfo_with_the_DPoP_scheme_and_a_proof_from_its_key()
    {
        await using var call = await BoundUserInfoTokenAsync();
        var proof = call.Key.Proof(call.Flow.UserInfoUrl, call.Flow.Now, htm: "GET", accessToken: call.AccessToken);

        using var response = await UserInfoAsync(call.Flow, "DPoP " + call.AccessToken, proof);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.TryGetProperty("sub", out _));
    }

    [DockerFact]
    public async Task A_bound_token_sent_as_a_bearer_token_is_refused()
    {
        await using var call = await BoundUserInfoTokenAsync();

        using var response = await UserInfoAsync(call.Flow, "Bearer " + call.AccessToken);

        AssertChallenge(response, "Bearer error=\"invalid_token\"");
    }

    [DockerFact]
    public async Task A_bound_token_needs_a_proof_for_this_token_and_this_request()
    {
        await using var call = await BoundUserInfoTokenAsync();
        var flow = call.Flow;
        using var thiefKey = new ClientKey();

        using var noProof = await UserInfoAsync(flow, "DPoP " + call.AccessToken);
        using var noAth = await UserInfoAsync(flow, "DPoP " + call.AccessToken, call.Key.Proof(flow.UserInfoUrl, flow.Now, htm: "GET"));
        using var wrongMethod = await UserInfoAsync(flow, "DPoP " + call.AccessToken, call.Key.Proof(flow.UserInfoUrl, flow.Now, accessToken: call.AccessToken));
        using var otherKey = await UserInfoAsync(flow, "DPoP " + call.AccessToken, thiefKey.Proof(flow.UserInfoUrl, flow.Now, htm: "GET", accessToken: call.AccessToken));

        const string Challenge = "DPoP algs=\"ES256 RS256\", error=\"invalid_dpop_proof\"";
        AssertChallenge(noProof, Challenge);
        AssertChallenge(noAth, Challenge);
        AssertChallenge(wrongMethod, Challenge);
        AssertChallenge(otherKey, Challenge);
    }

    [DockerFact]
    public async Task A_userinfo_proof_works_once()
    {
        await using var call = await BoundUserInfoTokenAsync();
        var proof = call.Key.Proof(call.Flow.UserInfoUrl, call.Flow.Now, htm: "GET", accessToken: call.AccessToken);

        using var first = await UserInfoAsync(call.Flow, "DPoP " + call.AccessToken, proof);
        using var replay = await UserInfoAsync(call.Flow, "DPoP " + call.AccessToken, proof);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        AssertChallenge(replay, "DPoP algs=\"ES256 RS256\", error=\"invalid_dpop_proof\"");
    }

    [DockerFact]
    public async Task A_request_without_a_token_gets_both_challenges()
    {
        await using var flow = await SetUpAsync();

        using var response = await UserInfoAsync(flow, authorization: null);

        AssertChallenge(response, "Bearer, DPoP algs=\"ES256 RS256\"");
    }

    [DockerFact]
    public async Task Discovery_lists_the_DPoP_proof_algorithms()
    {
        await using var flow = await SetUpAsync();

        using var response = await flow.Http.GetAsync(".well-known/openid-configuration");

        var algs = (await OkBodyAsync(response)).GetProperty("dpop_signing_alg_values_supported");
        Assert.Equal(["ES256", "RS256"], algs.EnumerateArray().Select(a => a.GetString()));
    }
}
