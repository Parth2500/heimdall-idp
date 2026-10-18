using System.Net;
using System.Text.Json;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// Refresh token rotation with family-based theft detection. Each test maps to a row of "Refresh flow" in the
/// threat model.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class RefreshRotationTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public RefreshRotationTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, HttpClient Http, string RefreshToken) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    /// <summary>Signs in, gets a code with offline_access, and redeems it. Returns the first refresh token.</summary>
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
            ["scope"] = "openid profile offline_access",
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
        return new Flow(api, tenant, http, body.GetProperty("refresh_token").GetString()!);
    }

    private static Task<HttpResponseMessage> RefreshAsync(Flow flow, string refreshToken, string clientId = "web-app", string? scope = null)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
            new("client_id", clientId),
        };
        if (scope is not null)
        {
            form.Add(new("scope", scope));
        }

        return flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(form));
    }

    private static async Task<string> NextRefreshTokenAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;
    }

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("""{"error":"invalid_grant"}""", await response.Content.ReadAsStringAsync());
    }

    private static async Task<TokenFamily> FamilyAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.AsNoTracking().SingleAsync();
    }

    [DockerFact]
    public async Task Each_use_returns_a_new_refresh_token_and_a_new_access_token()
    {
        await using var flow = await SetUpAsync();

        using var first = await RefreshAsync(flow, flow.RefreshToken);
        var second = await NextRefreshTokenAsync(first);
        using var third = await RefreshAsync(flow, second);

        Assert.NotEqual(flow.RefreshToken, second);
        Assert.Equal(HttpStatusCode.OK, third.StatusCode);
        Assert.True(first.Headers.CacheControl?.NoStore);
        var body = JsonDocument.Parse(await first.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("openid profile offline_access", body.GetProperty("scope").GetString());
        Assert.True(body.TryGetProperty("access_token", out _));

        // Rotation links the used token to its replacement.
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        var tokens = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().RefreshTokens.AsNoTracking().ToListAsync();
        Assert.Equal(3, tokens.Count);
        Assert.Single(tokens, t => t.UsedAt is null);
        Assert.Equal(2, tokens.Count(t => t.ReplacedById is not null));
    }

    [DockerFact]
    public async Task Reuse_of_a_used_token_revokes_the_whole_family_with_no_grace_window()
    {
        // The thief and the real client both hold the first token. Whoever comes second triggers the revocation, and
        // the newest token, held by the other party, stops working too.
        await using var flow = await SetUpAsync();
        using var legit = await RefreshAsync(flow, flow.RefreshToken);
        var newest = await NextRefreshTokenAsync(legit);

        using var replay = await RefreshAsync(flow, flow.RefreshToken);
        using var afterRevoke = await RefreshAsync(flow, newest);

        await AssertInvalidGrantAsync(replay);
        await AssertInvalidGrantAsync(afterRevoke);
        Assert.Equal(FamilyRevocationReason.ReuseDetected, (await FamilyAsync(flow)).RevocationReason);

        await using var scope = flow.Api.Services.CreateAsyncScope();
        var audit = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking();
        Assert.True(await audit.AnyAsync(e => e.TenantId == flow.Tenant.Tenant.Id && e.Type == AuditEventTypes.RefreshReuseDetected));
    }

    [DockerFact]
    public async Task Concurrent_uses_of_one_token_give_one_rotation_and_revoke_the_family()
    {
        await using var flow = await SetUpAsync();

        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => RefreshAsync(flow, flow.RefreshToken)));

        Assert.Equal(1, responses.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(7, responses.Count(r => r.StatusCode == HttpStatusCode.BadRequest));
        Assert.Equal(FamilyRevocationReason.ReuseDetected, (await FamilyAsync(flow)).RevocationReason);
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    [DockerFact]
    public async Task Token_of_one_client_cannot_be_used_or_burned_by_another()
    {
        await using var flow = await SetUpAsync();

        using var other = await RefreshAsync(flow, flow.RefreshToken, clientId: "other-app");
        using var right = await RefreshAsync(flow, flow.RefreshToken);

        await AssertInvalidGrantAsync(other);
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
        Assert.Null((await FamilyAsync(flow)).RevokedAt);
    }

    [DockerFact]
    public async Task Refresh_can_reduce_the_scope_but_never_widen_it()
    {
        await using var flow = await SetUpAsync();

        using var wider = await RefreshAsync(flow, flow.RefreshToken, scope: "openid profile offline_access email");
        Assert.Equal(HttpStatusCode.BadRequest, wider.StatusCode);
        Assert.Contains("invalid_scope", await wider.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        // The refused request did not use the token: it still rotates.
        using var narrower = await RefreshAsync(flow, flow.RefreshToken, scope: "openid");
        Assert.Equal(HttpStatusCode.OK, narrower.StatusCode);
        Assert.Equal("openid", JsonDocument.Parse(await narrower.Content.ReadAsStringAsync()).RootElement.GetProperty("scope").GetString());
    }

    [DockerFact]
    public async Task Family_ends_at_the_idle_limit()
    {
        await using var flow = await SetUpAsync();
        flow.Api.Time.Advance(flow.Tenant.Tenant.Settings.RefreshIdle);

        using var response = await RefreshAsync(flow, flow.RefreshToken);

        await AssertInvalidGrantAsync(response);
    }

    [DockerFact]
    public async Task Rotation_never_moves_the_absolute_limit()
    {
        // Rotate just inside the idle limit, again and again. The family still ends at its absolute limit.
        await using var flow = await SetUpAsync();
        var settings = flow.Tenant.Tenant.Settings;
        var step = settings.RefreshIdle - TimeSpan.FromHours(1);
        var token = flow.RefreshToken;
        var elapsed = TimeSpan.Zero;
        while (elapsed + step < settings.RefreshAbsolute)
        {
            flow.Api.Time.Advance(step);
            elapsed += step;
            using var rotated = await RefreshAsync(flow, token);
            token = await NextRefreshTokenAsync(rotated);
        }

        flow.Api.Time.Advance(settings.RefreshAbsolute - elapsed);
        using var expired = await RefreshAsync(flow, token);

        await AssertInvalidGrantAsync(expired);
        Assert.Null((await FamilyAsync(flow)).RevokedAt); // Expired, not revoked: no reuse happened.
    }

    [DockerFact]
    public async Task Disabled_user_cannot_refresh_and_the_family_ends()
    {
        await using var flow = await SetUpAsync();
        await using (var scope = flow.Api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
            var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
            var user = await users.FindByEmailAsync(flow.Tenant.Tenant.Id, Email, CancellationToken.None);
            user!.Disable();
            await users.SaveChangesAsync(CancellationToken.None);
        }

        using var response = await RefreshAsync(flow, flow.RefreshToken);

        await AssertInvalidGrantAsync(response);
        Assert.Equal(FamilyRevocationReason.UserDisabled, (await FamilyAsync(flow)).RevocationReason);
    }

    [DockerFact]
    public async Task Unknown_refresh_token_is_refused()
    {
        await using var flow = await SetUpAsync();

        using var response = await RefreshAsync(flow, new string('r', 43));

        await AssertInvalidGrantAsync(response);
        Assert.Null((await FamilyAsync(flow)).RevokedAt);
    }
}
