using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Keys;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Heimdall.IntegrationTests;

/// <summary>
/// The full signing path: key file, <c>signing_keys</c>, key cache, and signer. An independent JWT library checks
/// each token, so a bug in Heimdall's own JWT code cannot hide behind Heimdall's own check.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class TokenSigningTests
{
    private const string Audience = "https://api.example.com";
    private static readonly SigningKeyOptions KeyOptions = new()
    {
        JwksCacheLifetime = TimeSpan.FromMinutes(10),
        ServerCacheLifetime = TimeSpan.FromMinutes(1),
    };

    private readonly PostgresFixture _postgres;
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);

    public TokenSigningTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static string IssuerOf(Tenant tenant) => $"https://{tenant.Host}";

    private ServiceProvider Server() => _postgres.CreateServices(_time, KeyOptions);

    private static AccessTokenClaims Claims(Tenant tenant, params string[] scopes)
    {
        // Real time, because the independent validator checks exp against the real clock.
        var now = DateTimeOffset.UtcNow;
        return new AccessTokenClaims(
            IssuerOf(tenant),
            "billing-service",
            Audience,
            "billing-service",
            scopes,
            now,
            now.AddMinutes(5),
            Guid.NewGuid().ToString("N"));
    }

    private static async Task<Tenant> AddTenantAsync(ServiceProvider services)
    {
        var tenant = TestData.NewTenant();
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();
        return tenant;
    }

    /// <summary>Creates a key and activates it after its JWKS wait. Returns the key as stored.</summary>
    private async Task<SigningKey> AddActiveKeyAsync(ServiceProvider services, Tenant tenant)
    {
        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
        var keyService = scope.ServiceProvider.GetRequiredService<SigningKeyService>();

        var key = await keyService.CreateKeyAsync(tenant.Id, "test", CancellationToken.None);
        _time.Advance(KeyOptions.PublishWait);
        Assert.NotNull(await keyService.ActivateFirstKeyAsync(tenant.Id, "test", CancellationToken.None));
        return key;
    }

    private static async Task<string> SignAsync(ServiceProvider services, Tenant tenant, AccessTokenClaims claims) =>
        await services.GetRequiredService<ITokenSigner>().SignAccessTokenAsync(tenant.Id, claims, CancellationToken.None);

    private static Task<TokenValidationResult> ValidateAsync(string token, Tenant tenant, params SigningKey[] keys) =>
        new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = IssuerOf(tenant),
            ValidAudience = Audience,
            ValidAlgorithms = ["RS256"],
            ValidTypes = ["at+jwt"],
            IssuerSigningKeys = keys.Select(k => new JsonWebKey(k.PublicJwk)).ToList(),
            RequireSignedTokens = true,
            RequireExpirationTime = true,
        });

    [DockerFact]
    public async Task Token_passes_an_independent_RFC_9068_check()
    {
        await using var server = Server();
        var tenant = await AddTenantAsync(server);
        var key = await AddActiveKeyAsync(server, tenant);
        var claims = Claims(tenant, "invoices.read", "invoices.write");

        var token = await SignAsync(server, tenant, claims);
        var result = await ValidateAsync(token, tenant, key);

        Assert.True(result.IsValid, result.Exception?.Message);
        var jwt = (JsonWebToken)result.SecurityToken;
        Assert.Equal("RS256", jwt.Alg);
        Assert.Equal(key.Kid, jwt.Kid);
        Assert.Equal("at+jwt", jwt.Typ);
        Assert.Equal("billing-service", jwt.Subject);
        Assert.Equal("billing-service", jwt.GetClaim("client_id").Value);
        Assert.Equal("invoices.read invoices.write", jwt.GetClaim("scope").Value);
        Assert.Equal(claims.JwtId, jwt.Id);
        Assert.Equal(claims.IssuedAt.ToUnixTimeSeconds(), jwt.GetPayloadValue<long>("iat"));
        Assert.Equal(claims.ExpiresAt.ToUnixTimeSeconds(), jwt.GetPayloadValue<long>("exp"));
    }

    [DockerFact]
    public async Task Changed_payload_fails_the_signature_check()
    {
        await using var server = Server();
        var tenant = await AddTenantAsync(server);
        var key = await AddActiveKeyAsync(server, tenant);
        var token = await SignAsync(server, tenant, Claims(tenant, "invoices.read"));

        var parts = token.Split('.');
        var forgedClaims = Claims(tenant, "invoices.read", "admin") with { JwtId = "forged" };
        var forgedPayload = (await SignAsync(server, tenant, forgedClaims)).Split('.')[1];
        var forged = $"{parts[0]}.{forgedPayload}.{parts[2]}";

        var result = await ValidateAsync(forged, tenant, key);

        Assert.False(result.IsValid);
        Assert.IsAssignableFrom<SecurityTokenInvalidSignatureException>(result.Exception);
    }

    [DockerFact]
    public async Task Pending_key_does_not_sign()
    {
        await using var server = Server();
        var tenant = await AddTenantAsync(server);
        await using (var scope = server.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
            await scope.ServiceProvider.GetRequiredService<SigningKeyService>().CreateKeyAsync(tenant.Id, "test", CancellationToken.None);
        }

        var error = await Assert.ThrowsAsync<SigningKeyUnavailableException>(() => SignAsync(server, tenant, Claims(tenant)));

        Assert.Equal(tenant.Id, error.TenantId);
    }

    [DockerFact]
    public async Task Token_of_one_tenant_does_not_verify_with_the_key_of_another()
    {
        await using var server = Server();
        var tenantA = await AddTenantAsync(server);
        var tenantB = await AddTenantAsync(server);
        var keyA = await AddActiveKeyAsync(server, tenantA);
        var keyB = await AddActiveKeyAsync(server, tenantB);

        var token = await SignAsync(server, tenantA, Claims(tenantA));

        Assert.NotEqual(keyA.Kid, keyB.Kid);
        Assert.Equal(keyA.Kid, new JsonWebToken(token).Kid);
        Assert.False((await ValidateAsync(token, tenantA, keyB)).IsValid);
    }

    [DockerFact]
    public async Task Rotation_with_invalidation_switches_the_key_at_once()
    {
        await using var server = Server();
        var tenant = await AddTenantAsync(server);
        var oldKey = await AddActiveKeyAsync(server, tenant);

        SigningKey newKey;
        await using (var scope = server.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
            newKey = await scope.ServiceProvider.GetRequiredService<SigningKeyService>().CreateKeyAsync(tenant.Id, "test", CancellationToken.None);
        }

        _time.Advance(KeyOptions.PublishWait);

        // The cache now holds the old key, loaded after the JWKS wait.
        var before = await SignAsync(server, tenant, Claims(tenant));
        Assert.Equal(oldKey.Kid, new JsonWebToken(before).Kid);

        // Rotation is not a use case yet, so the test applies the Domain rule and invalidates the cache itself.
        await using (var scope = server.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var keys = await db.SigningKeys.Where(k => k.TenantId == tenant.Id).ToListAsync();
            SigningKeyRotation.Rotate(
                keys.Single(k => k.Id == oldKey.Id),
                keys.Single(k => k.Id == newKey.Id),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromMinutes(1),
                _time.GetUtcNow());
            await db.SaveChangesAsync();
        }

        server.GetRequiredService<ISigningKeyCache>().Invalidate(tenant.Id);
        var after = await SignAsync(server, tenant, Claims(tenant));

        // No time passed. The new key signs, and a verifier with both published keys accepts both tokens.
        Assert.Equal(newKey.Kid, new JsonWebToken(after).Kid);
        Assert.True((await ValidateAsync(before, tenant, oldKey, newKey)).IsValid);
        Assert.True((await ValidateAsync(after, tenant, oldKey, newKey)).IsValid);
    }

    [DockerFact]
    public async Task Server_keeps_its_cached_key_until_the_cache_lifetime_ends()
    {
        await using var serverA = Server();
        await using var serverB = Server();
        var tenant = await AddTenantAsync(serverA);
        var key = await AddActiveKeyAsync(serverA, tenant);
        Assert.Equal(key.Kid, new JsonWebToken(await SignAsync(serverB, tenant, Claims(tenant))).Kid);

        // Emergency removal on server A. Server B is not told.
        await using (var scope = serverA.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Id);
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            var stored = await db.SigningKeys.SingleAsync(k => k.Id == key.Id);
            stored.RemoveNow(_time.GetUtcNow());
            await db.SaveChangesAsync();
        }

        // Within the server cache lifetime, server B still signs with the removed key. This is the documented limit.
        _time.Advance(KeyOptions.ServerCacheLifetime - TimeSpan.FromSeconds(1));
        Assert.Equal(key.Kid, new JsonWebToken(await SignAsync(serverB, tenant, Claims(tenant))).Kid);

        // After it, server B reloads and stops signing.
        _time.Advance(TimeSpan.FromSeconds(1));
        await Assert.ThrowsAsync<SigningKeyUnavailableException>(() => SignAsync(serverB, tenant, Claims(tenant)));
    }
}
