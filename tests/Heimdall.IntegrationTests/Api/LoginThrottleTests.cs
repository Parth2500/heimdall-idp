using System.Net;
using Heimdall.Application.Users;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>The sign-in throttle for each account and source, against PostgreSQL (CLAUDE.md, abuse principles).</summary>
[Collection(PostgresGroup.Name)]
public sealed class LoginThrottleTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";

    private readonly PostgresFixture _postgres;

    public LoginThrottleTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task After_the_free_failures_even_the_right_password_waits_then_works()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddUserAsync(tenant, Email, Password);
        using var browser = new BrowserSession(api, tenant.Host);
        var options = api.Services.GetRequiredService<LoginThrottleOptions>();

        for (var i = 0; i <= options.FreeFailures; i++)
        {
            using var wrong = await browser.LoginAsync(Email, "wrong password value");
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        using var waiting = await browser.LoginAsync(Email, Password);
        api.Time.Advance(TimeSpan.FromSeconds(1));
        using var afterWait = await browser.LoginAsync(Email, Password);

        // The same answer as a wrong password: the caller cannot tell a throttled account from a wrong guess.
        Assert.Equal(HttpStatusCode.Unauthorized, waiting.StatusCode);
        Assert.Equal("""{"error":"invalid_credentials"}""", await waiting.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NoContent, afterWait.StatusCode);
    }

    [DockerFact]
    public async Task Concurrent_failures_from_two_servers_are_all_counted()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var user = await api.AddUserAsync(tenant, Email, Password);
        var now = api.Time.GetUtcNow();

        await Task.WhenAll(Enumerable.Range(0, 10).Select(async _ =>
        {
            await using var scope = api.Services.CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
            await scope.ServiceProvider.GetRequiredService<ILoginThrottleStore>()
                .RecordFailureAsync(tenant.Tenant.Id, user.Id, "198.51.100.7", now, now.AddDays(-1), CancellationToken.None);
        }));

        await using var read = api.Services.CreateAsyncScope();
        read.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var row = await read.ServiceProvider.GetRequiredService<HeimdallDbContext>().LoginThrottles.AsNoTracking().SingleAsync();
        Assert.Equal(10, row.Failures);
    }

    [DockerFact]
    public async Task Throttle_rows_are_invisible_to_another_tenant_and_old_ones_are_purged()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var other = await api.AddTenantAsync();
        var user = await api.AddUserAsync(tenant, Email, Password);
        var now = api.Time.GetUtcNow();
        await using (var scope = api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
            await scope.ServiceProvider.GetRequiredService<ILoginThrottleStore>()
                .RecordFailureAsync(tenant.Tenant.Id, user.Id, "198.51.100.7", now, now.AddDays(-1), CancellationToken.None);
        }

        // Row-level security: tenant B's context sees nothing, even without the query filter.
        await using (var scope = api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(other.Tenant.Id);
            Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().LoginThrottles.IgnoreQueryFilters().CountAsync());
        }

        api.Time.Advance(api.Services.GetRequiredService<LoginThrottleOptions>().ResetAfter + TimeSpan.FromMinutes(1));
        await using (var scope = api.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<Heimdall.Infrastructure.Purge.DataPurger>().RunOnceAsync(CancellationToken.None);
        }

        await using var check = api.Services.CreateAsyncScope();
        check.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        Assert.Equal(0, await check.ServiceProvider.GetRequiredService<HeimdallDbContext>().LoginThrottles.CountAsync());
    }
}
