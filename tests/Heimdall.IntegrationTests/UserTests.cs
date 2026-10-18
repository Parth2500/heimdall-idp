using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.Users;
using Heimdall.Domain.Users;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Heimdall.IntegrationTests;

/// <summary>The users table and sign-in with the real hasher.</summary>
[Collection(PostgresGroup.Name)]
public sealed class UserTests
{
    private const string Password = "correct horse battery staple";

    private readonly PostgresFixture _postgres;

    public UserTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static async Task<Guid> AddTenantAsync(ServiceProvider services)
    {
        var tenant = TestData.NewTenant();
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();
        return tenant.Id;
    }

    private static async Task<User> AddUserAsync(ServiceProvider services, Guid tenantId, string email, IPasswordHasher? hasher = null)
    {
        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        var hash = await (hasher ?? scope.ServiceProvider.GetRequiredService<IPasswordHasher>()).HashAsync(Password, CancellationToken.None);
        var user = User.Create(Guid.CreateVersion7(), tenantId, email, hash, TestData.Now);
        var store = scope.ServiceProvider.GetRequiredService<IUserStore>();
        store.Add(user);
        await store.SaveChangesAsync(CancellationToken.None);
        return user;
    }

    private static async Task<LoginResult> LoginAsync(ServiceProvider services, Guid tenantId, string email, string password)
    {
        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var tenant = await db.Tenants.SingleAsync(t => t.Id == tenantId);
        var context = new RequestContext(tenant, "https://" + tenant.Host, "corr-" + Guid.NewGuid().ToString("N"), IPAddress.Loopback);
        return await scope.ServiceProvider.GetRequiredService<UserAuthenticator>()
            .AuthenticateAsync(context, email, password, CancellationToken.None);
    }

    [DockerFact]
    public async Task Same_email_twice_in_one_tenant_is_refused_in_any_case()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        var tenantId = await AddTenantAsync(services);
        await AddUserAsync(services, tenantId, "alice@example.com");

        await Assert.ThrowsAsync<ConcurrentUpdateException>(() => AddUserAsync(services, tenantId, "ALICE@example.com"));
    }

    [DockerFact]
    public async Task Same_email_in_two_tenants_is_two_accounts()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        var tenantA = await AddTenantAsync(services);
        var tenantB = await AddTenantAsync(services);
        var userA = await AddUserAsync(services, tenantA, "alice@example.com");

        // D19: a user pool for each tenant. Tenant B cannot see tenant A's user.
        Assert.False((await LoginAsync(services, tenantB, "alice@example.com", Password)).Succeeded);

        var userB = await AddUserAsync(services, tenantB, "alice@example.com");
        Assert.NotEqual(userA.Id, userB.Id);
        Assert.Equal(userB.Id, (await LoginAsync(services, tenantB, "alice@example.com", Password)).User?.Id);
    }

    [DockerFact]
    public async Task Sign_in_works_with_the_real_hasher()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        var tenantId = await AddTenantAsync(services);
        var user = await AddUserAsync(services, tenantId, "bob@example.com");

        Assert.Equal(user.Id, (await LoginAsync(services, tenantId, "Bob@Example.com", Password)).User?.Id);
        Assert.False((await LoginAsync(services, tenantId, "bob@example.com", "wrong password here")).Succeeded);
        Assert.False((await LoginAsync(services, tenantId, "nobody@example.com", Password)).Succeeded);
    }

    [DockerFact]
    public async Task Sign_in_upgrades_an_old_hash_and_keeps_the_password_change_time()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        var tenantId = await AddTenantAsync(services);
        using var weak = new Argon2idPasswordHasher(new PasswordHashingOptions { MemoryKiB = 19 * 1024, Iterations = 3 });
        await AddUserAsync(services, tenantId, "carol@example.com", weak);

        Assert.True((await LoginAsync(services, tenantId, "carol@example.com", Password)).Succeeded);

        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
        var stored = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().Users.AsNoTracking()
            .SingleAsync(u => u.EmailNormalized == "carol@example.com");
        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", stored.PasswordHash, StringComparison.Ordinal);
        Assert.Equal(TestData.Now, stored.PasswordChangedAt);
    }

    [DockerFact]
    public async Task Database_refuses_a_password_hash_that_is_not_Argon2id()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        var tenantId = await AddTenantAsync(services);
        await using var connection = new NpgsqlConnection(_postgres.AdminConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO users (id, tenant_id, email, email_normalized, password_hash, status, created_at, password_changed_at)
            VALUES (@id, @tenant, 'x@example.com', 'x@example.com', 'plain-text-password', 'active', now(), now())
            """,
            connection);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("tenant", tenantId);

        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, exception.SqlState);
    }
}
