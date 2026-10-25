using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// The full authorization code flow with PKCE: sign in, /authorize, then /token. The redemption is one atomic
/// conditional UPDATE. Reuse revokes the family that the code started. Each test maps to a row of the /token table.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class CodeRedemptionTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Audience = "https://api.example.com";

    // RFC 7636, appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public CodeRedemptionTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser, HttpClient Http) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    private async Task<Flow> SetUpAsync()
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        await api.AddWebClientAsync(tenant, clientId: "other-app");
        await api.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return new Flow(api, tenant, browser, api.ClientFor(tenant.Host));
    }

    private static async Task<string> GetCodeAsync(Flow flow, string scope = "openid profile offline_access", string? nonce = "n-0S6_WzA2Mj")
    {
        var parameters = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = scope,
            ["state"] = "s1",
            ["nonce"] = nonce,
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        };
        using var response = await flow.Browser.SendAsync(
            HttpMethod.Get,
            QueryHelpers.AddQueryString("oauth/v1/authorize", parameters.Where(p => p.Value is not null)));
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
    }

    private static Task<HttpResponseMessage> RedeemAsync(
        Flow flow,
        string code,
        string verifier = Verifier,
        string clientId = "web-app",
        string redirectUri = Callback) =>
        flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", verifier),
            new("redirect_uri", redirectUri),
            new("client_id", clientId),
        ]));

    private static async Task<JsonElement> JsonOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        // D5: the same answer for unknown, expired, reused, and mismatched codes.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("""{"error":"invalid_grant"}""", await response.Content.ReadAsStringAsync());
    }

    private static async Task<AuthorizationCode> StoredCodeAsync(Flow flow, string code)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        var codes = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuthorizationCodes.AsNoTracking().ToListAsync();
        return codes.Single(c => c.CodeHash.AsSpan().SequenceEqual(hash));
    }

    private static async Task<TokenFamily> FamilyAsync(Flow flow, Guid familyId)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.AsNoTracking().SingleAsync(f => f.Id == familyId);
    }

    private static async Task<TokenValidationResult> ValidateAsync(Flow flow, string token, string audience, string type)
    {
        var jwks = new JsonWebKeySet(await flow.Http.GetStringAsync(".well-known/jwks.json"));
        return await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = flow.Tenant.Issuer,
            ValidAudience = audience,
            ValidAlgorithms = ["RS256"],
            ValidTypes = [type],
            IssuerSigningKeys = jwks.GetSigningKeys(),
            LifetimeValidator = (_, _, _, _) => true,
        });
    }

    [DockerFact]
    public async Task Code_gives_an_access_token_an_id_token_and_a_refresh_token()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        using var response = await RedeemAsync(flow, code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = await JsonOf(response);
        Assert.Equal("openid profile offline_access", body.GetProperty("scope").GetString());

        var access = await ValidateAsync(flow, body.GetProperty("access_token").GetString()!, Audience, "at+jwt");
        Assert.True(access.IsValid, access.Exception?.Message);
        var accessJwt = (JsonWebToken)access.SecurityToken;
        Assert.Equal("web-app", accessJwt.GetClaim("client_id").Value);
        Assert.True(accessJwt.TryGetPayloadValue<long>("auth_time", out _));

        var id = await ValidateAsync(flow, body.GetProperty("id_token").GetString()!, "web-app", "JWT");
        Assert.True(id.IsValid, id.Exception?.Message);
        var idJwt = (JsonWebToken)id.SecurityToken;
        Assert.Equal(accessJwt.Subject, idJwt.Subject);
        Assert.Equal("n-0S6_WzA2Mj", idJwt.GetClaim("nonce").Value);

        // The code is redeemed and linked to its family. Only the refresh token's hash is stored.
        var stored = await StoredCodeAsync(flow, code);
        Assert.NotNull(stored.RedeemedAt);
        var family = await FamilyAsync(flow, stored.FamilyId!.Value);

        // D29: the ID token names the session, the family records it, and the access token names the family.
        Assert.Matches("^[A-Za-z0-9_-]{22}$", idJwt.GetClaim("sid").Value);
        Assert.Equal(idJwt.GetClaim("sid").Value, stored.Sid);
        Assert.Equal(stored.Sid, family.Sid);
        Assert.Equal(family.Id.ToString("N"), accessJwt.GetClaim("fid").Value);
        Assert.True(family.IsActive(flow.Api.Time.GetUtcNow()));
        Assert.Equal(43, body.GetProperty("refresh_token").GetString()!.Length);
    }

    [DockerFact]
    public async Task Without_offline_access_there_is_no_refresh_token()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow, scope: "openid");

        using var response = await RedeemAsync(flow, code);

        var body = await JsonOf(response);
        Assert.False(body.TryGetProperty("refresh_token", out _));
        Assert.True(body.TryGetProperty("id_token", out _));
    }

    [DockerFact]
    public async Task Reused_code_is_refused_and_revokes_the_family_it_started()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);
        using var first = await RedeemAsync(flow, code);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        using var second = await RedeemAsync(flow, code);

        await AssertInvalidGrantAsync(second);
        var stored = await StoredCodeAsync(flow, code);
        var family = await FamilyAsync(flow, stored.FamilyId!.Value);
        Assert.Equal(FamilyRevocationReason.ReuseDetected, family.RevocationReason);

        await using var scope = flow.Api.Services.CreateAsyncScope();
        var audit = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking();
        Assert.True(await audit.AnyAsync(e => e.FamilyId == family.Id && e.Type == AuditEventTypes.CodeReuseDetected));
        Assert.True(await audit.AnyAsync(e => e.FamilyId == family.Id && e.Type == AuditEventTypes.FamilyRevoked));
    }

    [DockerFact]
    public async Task Concurrent_redemptions_give_one_set_of_tokens_and_revoke_its_family()
    {
        // The roadmap's concurrency test: many requests race for one code. The atomic UPDATE lets one win. The others
        // wait on the row lock, see the redeemed code, and treat it as reuse.
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => RedeemAsync(flow, code)));

        Assert.Equal(1, responses.Count(r => r.StatusCode == HttpStatusCode.OK));
        foreach (var refused in responses.Where(r => r.StatusCode != HttpStatusCode.OK))
        {
            await AssertInvalidGrantAsync(refused);
        }

        var stored = await StoredCodeAsync(flow, code);
        Assert.Equal(FamilyRevocationReason.ReuseDetected, (await FamilyAsync(flow, stored.FamilyId!.Value)).RevocationReason);

        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.CountAsync(f => f.SourceCodeId == stored.Id));
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    [DockerFact]
    public async Task Wrong_verifier_does_not_burn_the_code()
    {
        // A stolen code without the verifier is useless, and the attempt does not stop the real client.
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        using var wrong = await RedeemAsync(flow, code, verifier: new string('a', 43));
        using var right = await RedeemAsync(flow, code);

        await AssertInvalidGrantAsync(wrong);
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
    }

    [DockerFact]
    public async Task Code_of_one_client_cannot_be_redeemed_by_another()
    {
        // Confused deputy: the stored client must be the calling client.
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        using var other = await RedeemAsync(flow, code, clientId: "other-app");
        using var right = await RedeemAsync(flow, code);

        await AssertInvalidGrantAsync(other);
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
    }

    [DockerFact]
    public async Task Different_redirect_uri_is_refused()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        using var response = await RedeemAsync(flow, code, redirectUri: Callback + "/");

        await AssertInvalidGrantAsync(response);
    }

    [DockerFact]
    public async Task Expired_code_is_refused()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);
        flow.Api.Time.Advance(AuthorizationCode.Lifetime);

        using var response = await RedeemAsync(flow, code);

        await AssertInvalidGrantAsync(response);
    }

    [DockerFact]
    public async Task Unknown_code_is_refused()
    {
        await using var flow = await SetUpAsync();

        using var response = await RedeemAsync(flow, new string('x', 43));

        await AssertInvalidGrantAsync(response);
    }

    [DockerFact]
    public async Task Failed_signing_rolls_back_and_leaves_the_code_usable()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        // No key can sign: the emergency removal leaves only a pending replacement.
        await using (var scope = flow.Api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var kid = (await db.SigningKeys.AsNoTracking().SingleAsync()).Kid;
            await scope.ServiceProvider.GetRequiredService<Heimdall.Application.Keys.SigningKeyService>()
                .RemoveCompromisedKeyAsync(flow.Tenant.Tenant.Id, kid, "test", CancellationToken.None);
        }

        using var failed = await RedeemAsync(flow, code);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        var stored = await StoredCodeAsync(flow, code);
        Assert.Null(stored.RedeemedAt);
        Assert.Null(stored.FamilyId);
    }

    [DockerFact]
    public async Task Missing_verifier_is_invalid_request()
    {
        await using var flow = await SetUpAsync();
        var code = await GetCodeAsync(flow);

        using var response = await flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", Callback),
            new("client_id", "web-app"),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (await JsonOf(response)).GetProperty("error").GetString());
    }
}
