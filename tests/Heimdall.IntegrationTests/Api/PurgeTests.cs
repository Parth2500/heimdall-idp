using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Purge;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// The purge job (docs/schema-design.md, "Purge job"). Each row is created at a fixed age, then one pass runs. The
/// assertions look at this test's rows only: the database is shared with other tests.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class PurgeTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly TokenLifetimes Lifetimes = new(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(30));

    private readonly PostgresFixture _postgres;

    public PurgeTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Fixture(HeimdallApiFactory Api, Guid TenantId, Guid ClientPk, User User);

    private static async Task<Fixture> SetUpAsync(HeimdallApiFactory api)
    {
        var tenant = await api.AddTenantAsync();
        var client = await api.AddWebClientAsync(tenant);
        var user = await api.AddUserAsync(tenant, "alice@example.com", "correct horse battery staple");
        return new Fixture(api, tenant.Tenant.Id, client.Id, user);
    }

    private static async Task SaveAsync(Fixture fixture, Action<HeimdallDbContext> add)
    {
        await using var scope = fixture.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(fixture.TenantId);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        add(db);
        await db.SaveChangesAsync();
    }

    private static async Task<T> ReadAsync<T>(Fixture fixture, Func<HeimdallDbContext, Task<T>> read)
    {
        await using var scope = fixture.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(fixture.TenantId);
        return await read(scope.ServiceProvider.GetRequiredService<HeimdallDbContext>());
    }

    private static async Task<PurgeResult> PurgeAsync(Fixture fixture, PurgeOptions? options = null)
    {
        await using var scope = fixture.Api.Services.CreateAsyncScope();
        var purger = options is null
            ? scope.ServiceProvider.GetRequiredService<DataPurger>()
            : new DataPurger(scope.ServiceProvider.GetRequiredService<PlatformDbContextFactory>(), options, fixture.Api.Time);
        return await purger.RunOnceAsync(CancellationToken.None);
    }

    private static TokenFamily Family(Fixture fixture, DateTimeOffset start) =>
        TokenFamily.Start(Guid.CreateVersion7(), fixture.TenantId, fixture.ClientPk, fixture.User.Id, Guid.CreateVersion7(), "openid offline_access", Lifetimes, start);

    private static AuthorizationCode Code(Fixture fixture, DateTimeOffset created, Guid? familyId = null)
    {
        var code = AuthorizationCode.Create(
            Guid.CreateVersion7(),
            fixture.TenantId,
            fixture.ClientPk,
            fixture.User.Id,
            TokenHash.Compute(Guid.NewGuid().ToString()),
            "https://app.example.com/callback",
            "openid",
            Challenge,
            null,
            created,
            created);
        if (familyId is { } id)
        {
            code.Redeem(id, created);
        }

        return code;
    }

    [DockerFact]
    public async Task Families_end_plus_retention_are_deleted_with_their_tokens_and_free_their_codes()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var fixture = await SetUpAsync(api);
        var now = api.Time.GetUtcNow();

        var idleEnded = Family(fixture, now - TimeSpan.FromDays(40));
        var revokedLongAgo = Family(fixture, now - TimeSpan.FromDays(10));
        revokedLongAgo.Revoke(FamilyRevocationReason.UserLogout, now - TimeSpan.FromDays(9));
        var revokedRecently = Family(fixture, now - TimeSpan.FromDays(2));
        revokedRecently.Revoke(FamilyRevocationReason.ReuseDetected, now - TimeSpan.FromDays(1));
        var live = Family(fixture, now);

        // A rotated chain: the used token points at its replacement (replaced_by_id).
        var newest = RefreshToken.Create(Guid.CreateVersion7(), fixture.TenantId, idleEnded.Id, TokenHash.Compute("newest"), idleEnded.CreatedAt);
        var used = RefreshToken.Create(Guid.CreateVersion7(), fixture.TenantId, idleEnded.Id, TokenHash.Compute("used"), idleEnded.CreatedAt);
        used.Use(newest.Id, idleEnded.CreatedAt);

        var codeOfIdleEnded = Code(fixture, idleEnded.CreatedAt, idleEnded.Id);
        var codeOfLive = Code(fixture, now - TimeSpan.FromDays(2), live.Id);
        await SaveAsync(fixture, db =>
        {
            db.TokenFamilies.AddRange(idleEnded, revokedLongAgo, revokedRecently, live);
            db.RefreshTokens.AddRange(newest, used);
            db.AuthorizationCodes.AddRange(codeOfIdleEnded, codeOfLive);
        });

        await PurgeAsync(fixture);

        var families = await ReadAsync(fixture, db => db.TokenFamilies.Select(f => f.Id).ToListAsync());
        Assert.Equal(new[] { revokedRecently.Id, live.Id }.Order(), families.Order());
        Assert.Empty(await ReadAsync(fixture, db => db.RefreshTokens.ToListAsync()));

        // The family purge freed the code of the ended family. It was long expired, so the same pass deleted it.
        var codes = await ReadAsync(fixture, db => db.AuthorizationCodes.Select(c => c.Id).ToListAsync());
        Assert.Equal([codeOfLive.Id], codes);
    }

    [DockerFact]
    public async Task Codes_requests_and_sessions_are_deleted_only_after_their_retention()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var fixture = await SetUpAsync(api);
        var now = api.Time.GetUtcNow();

        var oldCode = Code(fixture, now - TimeSpan.FromDays(2));
        var recentCode = Code(fixture, now - TimeSpan.FromHours(1));
        var expiredRequest = AuthorizationRequest.Create(
            Guid.CreateVersion7(), fixture.TenantId, fixture.ClientPk, "https://app.example.com/callback", "openid", null, null, Challenge, false, null, now - TimeSpan.FromMinutes(11));
        var liveRequest = AuthorizationRequest.Create(
            Guid.CreateVersion7(), fixture.TenantId, fixture.ClientPk, "https://app.example.com/callback", "openid", null, null, Challenge, false, null, now);
        var oldSession = Session.Start(TokenHash.Compute("old"), fixture.TenantId, fixture.User.Id, TimeSpan.FromHours(12), now - TimeSpan.FromDays(9));
        var revokedRecently = Session.Start(TokenHash.Compute("revoked"), fixture.TenantId, fixture.User.Id, TimeSpan.FromHours(12), now - TimeSpan.FromDays(1));
        revokedRecently.Revoke(now - TimeSpan.FromDays(1));
        var liveSession = Session.Start(TokenHash.Compute("live"), fixture.TenantId, fixture.User.Id, TimeSpan.FromHours(12), now);
        await SaveAsync(fixture, db =>
        {
            db.AuthorizationCodes.AddRange(oldCode, recentCode);
            db.AuthorizationRequests.AddRange(expiredRequest, liveRequest);
            db.Sessions.AddRange(oldSession, revokedRecently, liveSession);
        });

        await PurgeAsync(fixture);

        Assert.Equal([recentCode.Id], await ReadAsync(fixture, db => db.AuthorizationCodes.Select(c => c.Id).ToListAsync()));
        Assert.Equal([liveRequest.Id], await ReadAsync(fixture, db => db.AuthorizationRequests.Select(r => r.Id).ToListAsync()));
        var sessions = await ReadAsync(fixture, db => db.Sessions.Select(s => s.IdHash).ToListAsync());
        Assert.Equal(2, sessions.Count);
        Assert.DoesNotContain(oldSession.IdHash, sessions);
    }

    [DockerFact]
    public async Task A_pass_repeats_small_batches_until_nothing_is_left()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var fixture = await SetUpAsync(api);
        var now = api.Time.GetUtcNow();
        var requests = Enumerable.Range(0, 5)
            .Select(_ => AuthorizationRequest.Create(
                Guid.CreateVersion7(), fixture.TenantId, fixture.ClientPk, "https://app.example.com/callback", "openid", null, null, Challenge, false, null, now - TimeSpan.FromHours(1)))
            .ToList();
        await SaveAsync(fixture, db => db.AuthorizationRequests.AddRange(requests));

        var result = await PurgeAsync(fixture, new PurgeOptions { BatchSize = 2 });

        Assert.True(result.Requests >= 5);
        Assert.Empty(await ReadAsync(fixture, db => db.AuthorizationRequests.ToListAsync()));
    }

    [Fact]
    public void Options_with_zero_retention_or_a_bad_batch_size_are_refused()
    {
        Assert.Empty(new PurgeOptions().Validate());
        Assert.Equal(2, new PurgeOptions { FamilyRetention = TimeSpan.Zero, BatchSize = 0 }.Validate().Count);
    }
}
