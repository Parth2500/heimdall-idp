using System.Net;
using System.Text.Json;
using Heimdall.Api.Jobs;
using Heimdall.Application.Common;
using Heimdall.Application.Keys;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// The signing key job and key rotation, against PostgreSQL and through the real endpoints. Each factory acts as one
/// server. The job also works on keys that other tests left in the shared database, so assertions look at one
/// tenant only.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class SigningKeyJobTests
{
    private readonly PostgresFixture _postgres;

    public SigningKeyJobTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static async Task<Guid> AddTenantWithoutKeysAsync(HeimdallApiFactory api)
    {
        var tenant = TestData.NewTenant();
        await using var scope = api.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();
        return tenant.Id;
    }

    private static async Task<List<SigningKey>> KeysOfAsync(HeimdallApiFactory api, Guid tenantId)
    {
        await using var scope = api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().SigningKeys.AsNoTracking().ToListAsync();
    }

    private static async Task<int> CountAuditAsync(HeimdallApiFactory api, Guid tenantId, string type)
    {
        await using var scope = api.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents
            .CountAsync(e => e.TenantId == tenantId && e.Type == type);
    }

    private static Task<int> RunJobAsync(HeimdallApiFactory api) =>
        api.Services.GetRequiredService<SigningKeyJob>().RunOnceAsync(CancellationToken.None);

    private static async Task<string> TokenAsync(HttpClient http, TestTenant tenant)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, tenant.ClientSecret);
        using var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("access_token").GetString()!;
    }

    private static async Task<HashSet<string?>> JwksKidsAsync(HttpClient http)
    {
        using var jwks = JsonDocument.Parse(await http.GetStringAsync(".well-known/jwks.json"));
        return jwks.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToHashSet();
    }

    private static async Task<bool> VerifiesAsync(HttpClient http, TestTenant tenant, string token)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = tenant.Issuer,
            ValidAudience = "https://api.example.com",
            ValidAlgorithms = ["RS256"],
            IssuerSigningKeys = new JsonWebKeySet(await http.GetStringAsync(".well-known/jwks.json")).GetSigningKeys(),
            LifetimeValidator = (_, _, _, _) => true,
        });
        return result.IsValid;
    }

    [DockerFact]
    public async Task Job_creates_a_first_key_and_activates_it_after_its_wait()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenantId = await AddTenantWithoutKeysAsync(api);

        await RunJobAsync(api);
        Assert.Equal(SigningKeyStatus.Pending, Assert.Single(await KeysOfAsync(api, tenantId)).Status);

        api.Time.Advance(api.KeyOptions.PublishWait - TimeSpan.FromSeconds(1));
        await RunJobAsync(api);
        Assert.Equal(SigningKeyStatus.Pending, Assert.Single(await KeysOfAsync(api, tenantId)).Status);

        api.Time.Advance(TimeSpan.FromSeconds(1));
        await RunJobAsync(api);
        Assert.Equal(SigningKeyStatus.Active, Assert.Single(await KeysOfAsync(api, tenantId)).Status);
    }

    [DockerFact]
    public async Task Two_servers_running_the_job_create_one_key_and_activate_it_once()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var serverA = new HeimdallApiFactory(_postgres, time);
        await using var serverB = new HeimdallApiFactory(_postgres, time);
        var tenantId = await AddTenantWithoutKeysAsync(serverA);

        await Task.WhenAll(RunJobAsync(serverA), RunJobAsync(serverB), RunJobAsync(serverA), RunJobAsync(serverB));
        time.Advance(serverA.KeyOptions.PublishWait);
        await Task.WhenAll(RunJobAsync(serverA), RunJobAsync(serverB), RunJobAsync(serverA), RunJobAsync(serverB));

        // Whatever the interleaving: one key, one creation event, one activation event.
        Assert.Equal(SigningKeyStatus.Active, Assert.Single(await KeysOfAsync(serverA, tenantId)).Status);
        Assert.Equal(1, await CountAuditAsync(serverA, tenantId, AuditEventTypes.KeyCreated));
        Assert.Equal(1, await CountAuditAsync(serverA, tenantId, AuditEventTypes.KeyActivated));
    }

    [DockerFact]
    public async Task Store_refuses_a_stale_status_change_and_a_second_pending_key()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenantId = await AddTenantWithoutKeysAsync(api);
        await RunJobAsync(api);
        api.Time.Advance(api.KeyOptions.PublishWait);

        await using var scopeA = api.Services.CreateAsyncScope();
        await using var scopeB = api.Services.CreateAsyncScope();
        scopeA.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        scopeB.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        var storeA = scopeA.ServiceProvider.GetRequiredService<ISigningKeyStore>();
        var storeB = scopeB.ServiceProvider.GetRequiredService<ISigningKeyStore>();

        // Both servers read the same pending key, and both activate it.
        var fromA = Assert.Single(await storeA.ListAsync(tenantId, CancellationToken.None));
        var fromB = Assert.Single(await storeB.ListAsync(tenantId, CancellationToken.None));
        SigningKeyRotation.ActivateFirst(fromA, api.Time.GetUtcNow());
        SigningKeyRotation.ActivateFirst(fromB, api.Time.GetUtcNow());

        await storeA.SaveChangesAsync(CancellationToken.None);
        await Assert.ThrowsAsync<ConcurrentUpdateException>(() => storeB.SaveChangesAsync(CancellationToken.None));

        // Two pending keys for one tenant.
        storeA.Add(SigningKey.Create(Guid.CreateVersion7(), tenantId, "p1", "{}", "devfile:p1", TimeSpan.FromMinutes(1), api.Time.GetUtcNow()));
        await storeA.SaveChangesAsync(CancellationToken.None);
        storeB.Add(SigningKey.Create(Guid.CreateVersion7(), tenantId, "p2", "{}", "devfile:p2", TimeSpan.FromMinutes(1), api.Time.GetUtcNow()));
        await Assert.ThrowsAsync<ConcurrentUpdateException>(() => storeB.SaveChangesAsync(CancellationToken.None));
    }

    [DockerFact]
    public async Task Work_list_has_only_tenants_that_need_key_work()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var settled = (await api.AddTenantAsync()).Tenant.Id;
        var noKeys = await AddTenantWithoutKeysAsync(api);

        await using var scope = api.Services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ISigningKeyStore>();
        var now = api.Time.GetUtcNow();
        var farFromRotation = now - api.KeyOptions.RotationInterval;
        var work = await store.ListTenantsNeedingKeyWorkAsync(now, farFromRotation, CancellationToken.None);

        Assert.Contains(noKeys, work);
        Assert.DoesNotContain(settled, work);

        // With a cutoff after the active key's start, the settled tenant is due for its next key.
        var due = await store.ListTenantsNeedingKeyWorkAsync(now, now, CancellationToken.None);
        Assert.Contains(settled, due);
    }

    [DockerFact]
    public async Task Rotation_keeps_old_tokens_valid_until_the_old_key_leaves_the_JWKS()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);
        var options = api.KeyOptions;
        var oldKid = Assert.Single(await KeysOfAsync(api, tenant.Tenant.Id)).Kid;
        var oldToken = await TokenAsync(http, tenant);

        // One publish wait before rotation is due, the job creates the next key. It is in the JWKS but does not sign.
        api.Time.Advance(options.RotationInterval - options.PublishWait);
        await RunJobAsync(api);
        var nextKid = (await KeysOfAsync(api, tenant.Tenant.Id)).Single(k => k.Status == SigningKeyStatus.Pending).Kid;
        Assert.Contains(nextKid, await JwksKidsAsync(http));
        Assert.Equal(oldKid, new JsonWebToken(await TokenAsync(http, tenant)).Kid);

        // At the rotation time, the next key signs. The old key stays in the JWKS, so old tokens still verify.
        api.Time.Advance(options.PublishWait);
        await RunJobAsync(api);
        var newToken = await TokenAsync(http, tenant);
        Assert.Equal(nextKid, new JsonWebToken(newToken).Kid);
        Assert.True((await JwksKidsAsync(http)).SetEquals([oldKid, nextKid]));
        Assert.True(await VerifiesAsync(http, tenant, oldToken));
        Assert.True(await VerifiesAsync(http, tenant, newToken));

        // After the longest token lifetime plus clock skew, the old key leaves the JWKS.
        api.Time.Advance(TimeSpan.FromMinutes(60) + options.ClockSkew);
        Assert.Equal([nextKid], await JwksKidsAsync(http));
        Assert.False(await VerifiesAsync(http, tenant, oldToken));
        Assert.True(await VerifiesAsync(http, tenant, newToken));
        Assert.Equal(1, await CountAuditAsync(api, tenant.Tenant.Id, AuditEventTypes.KeyRetired));
    }

    [DockerFact]
    public async Task Emergency_removal_stops_the_key_at_once_and_the_replacement_signs_after_its_wait()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);
        var stolenKid = Assert.Single(await KeysOfAsync(api, tenant.Tenant.Id)).Kid;
        var stolenToken = await TokenAsync(http, tenant);

        KeyRemovalResult result;
        await using (var scope = api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
            result = await scope.ServiceProvider.GetRequiredService<SigningKeyService>()
                .RemoveCompromisedKeyAsync(tenant.Tenant.Id, stolenKid, "test", CancellationToken.None);
        }

        // This server invalidated its cache, so the removal is visible at once.
        Assert.Equal(KeyMaintenanceAction.Created, result.Replacement);
        Assert.DoesNotContain(stolenKid, await JwksKidsAsync(http));
        Assert.False(await VerifiesAsync(http, tenant, stolenToken));

        // No key signs until the replacement's wait ends. Issuance fails closed.
        using (var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token"))
        {
            request.Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]);
            request.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, tenant.ClientSecret);
            using var refused = await http.SendAsync(request);
            Assert.Equal(HttpStatusCode.InternalServerError, refused.StatusCode);
        }

        api.Time.Advance(api.KeyOptions.PublishWait);
        await RunJobAsync(api);
        var token = await TokenAsync(http, tenant);
        Assert.NotEqual(stolenKid, new JsonWebToken(token).Kid);
        Assert.True(await VerifiesAsync(http, tenant, token));
        Assert.Equal(1, await CountAuditAsync(api, tenant.Tenant.Id, AuditEventTypes.KeyRemoved));
    }
}
