using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Heimdall.IntegrationTests;

/// <summary>
/// D20, second layer: PostgreSQL row-level security. Each test bypasses the EF Core tenant filter on purpose, as a bug
/// or a raw SQL statement would, and checks that PostgreSQL still keeps the tenants apart.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class RowLevelSecurityTests
{
    private readonly PostgresFixture _postgres;

    public RowLevelSecurityTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    /// <summary>Two tenants, one client each, created as the owner.</summary>
    private async Task<(Guid A, Guid B)> SeedAsync()
    {
        await using var services = _postgres.CreateServices(connectionString: _postgres.AdminConnectionString);
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var a = TestData.NewTenant();
        var b = TestData.NewTenant();
        db.Tenants.AddRange(a, b);
        db.Clients.AddRange(TestData.NewServiceClient(a.Id), TestData.NewServiceClient(b.Id));
        await db.SaveChangesAsync();
        return (a.Id, b.Id);
    }

    private static async Task<List<Guid>> ClientTenantsAsync(ServiceProvider services, Guid? tenant, Guid a, Guid b)
    {
        await using var scope = services.CreateAsyncScope();
        if (tenant is { } id)
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(id);
        }

        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().Clients
            .IgnoreQueryFilters()
            .Where(c => c.TenantId == a || c.TenantId == b)
            .Select(c => c.TenantId)
            .ToListAsync();
    }

    [DockerFact]
    public async Task Without_the_query_filter_a_context_still_sees_only_its_tenant()
    {
        var (a, b) = await SeedAsync();
        await using var services = _postgres.CreateServices();

        Assert.Equal([a], await ClientTenantsAsync(services, a, a, b));
        Assert.Equal([b], await ClientTenantsAsync(services, b, a, b));
    }

    [DockerFact]
    public async Task A_pooled_connection_does_not_keep_the_previous_tenant()
    {
        var (a, b) = await SeedAsync();

        // One pooled connection, so the second context gets the connection that the first one used. Npgsql resets the
        // session state of a returned connection by default. NoResetOnClose turns that off, so the interceptor alone
        // must clear the tenant, as it must for a deployment that sets this option for speed.
        var single = new NpgsqlConnectionStringBuilder(_postgres.ConnectionString) { MaxPoolSize = 1, NoResetOnClose = true }.ConnectionString;
        await using var services = _postgres.CreateServices(connectionString: single);

        Assert.Equal([a], await ClientTenantsAsync(services, a, a, b));
        Assert.Empty(await ClientTenantsAsync(services, tenant: null, a, b));
    }

    [DockerFact]
    public async Task Raw_sql_without_a_tenant_sees_no_rows_and_cannot_write()
    {
        var (a, b) = await SeedAsync();
        await using var connection = new NpgsqlConnection(_postgres.ConnectionString);
        await connection.OpenAsync();

        await using var count = new NpgsqlCommand("SELECT count(*) FROM clients WHERE tenant_id IN (@a, @b)", connection);
        count.Parameters.AddWithValue("a", a);
        count.Parameters.AddWithValue("b", b);
        Assert.Equal(0L, await count.ExecuteScalarAsync());

        await using var update = new NpgsqlCommand("UPDATE clients SET name = 'changed' WHERE tenant_id = @a", connection);
        update.Parameters.AddWithValue("a", a);
        Assert.Equal(0, await update.ExecuteNonQueryAsync());
    }

    [DockerFact]
    public async Task A_context_cannot_write_a_row_for_another_tenant()
    {
        var (a, b) = await SeedAsync();
        await using var services = _postgres.CreateServices();
        await using var scope = services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(a);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        db.Clients.Add(TestData.NewServiceClient(b, clientId: "planted-client"));

        var exception = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());

        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, Assert.IsType<PostgresException>(exception.InnerException).SqlState);
    }

    [DockerFact]
    public async Task The_platform_role_sees_every_tenant()
    {
        var (a, b) = await SeedAsync();
        await using var services = _postgres.CreateServices();

        await using var db = services.GetRequiredService<PlatformDbContextFactory>().Create();
        var tenants = await db.Clients.IgnoreQueryFilters().Where(c => c.TenantId == a || c.TenantId == b).Select(c => c.TenantId).ToListAsync();

        Assert.Equal(new[] { a, b }.Order(), tenants.Order());
    }

    [DockerFact]
    public async Task The_application_role_can_only_append_to_the_audit_log()
    {
        await using var services = _postgres.CreateServices();
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            db.AuditEvents.Add(AuditEvent.Record(Guid.CreateVersion7(), null, "test.append", "rls-test", TestData.Now));
            await db.SaveChangesAsync();
        }

        await using var connection = new NpgsqlConnection(_postgres.ConnectionString);
        await connection.OpenAsync();
        foreach (var sql in new[] { "UPDATE audit_events SET type = 'test.changed' WHERE type = 'test.append'", "DELETE FROM audit_events" })
        {
            await using var command = new NpgsqlCommand(sql, connection);
            var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, exception.SqlState);
        }
    }

    [DockerFact]
    public async Task Every_tenant_owned_table_has_row_level_security()
    {
        // A new table with a tenant_id column must get the same policies in its migration. This test finds one that
        // did not. audit_events is the documented exception: platform events have no tenant (docs/schema-design.md).
        await using var connection = new Npgsql.NpgsqlConnection(_postgres.AdminConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                   EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation')
            FROM   pg_class c
            JOIN   pg_namespace n ON n.oid = c.relnamespace
            WHERE  n.nspname = 'public' AND c.relkind = 'r'
              AND  EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
              AND  c.relname <> 'audit_events'
            ORDER  BY c.relname
            """;
        var tables = new List<(string Name, bool Enabled, bool Forced, bool Policy)>();
        await using (var reader = await command.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                tables.Add((reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2), reader.GetBoolean(3)));
            }
        }

        Assert.Contains(tables, t => t.Name == "dpop_proofs");
        Assert.All(tables, t => Assert.True(t.Enabled && t.Forced && t.Policy, $"{t.Name}: row-level security is not complete."));
    }
}
