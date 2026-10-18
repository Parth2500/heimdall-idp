using Heimdall.Domain.Keys;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Heimdall.IntegrationTests;

/// <summary>
/// The database repeats the important rules. These tests bypass the Domain with raw SQL, as a bug or a
/// manual change would, and check that PostgreSQL still refuses the row.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class ConstraintTests
{
    private const string CheckViolation = "23514";
    private const string UniqueViolation = "23505";
    private const string ForeignKeyViolation = "23503";

    private readonly PostgresFixture _postgres;

    public ConstraintTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private async Task<Guid> NewTenantAsync()
    {
        await using var services = _postgres.CreateServices();
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var tenant = TestData.NewTenant();
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();
        return tenant.Id;
    }

    private async Task<string?> InsertClientRawAsync(
        Guid tenantId,
        string type,
        string authMethod,
        string grantTypes,
        string audiences,
        string clientId = "raw-client")
    {
        await using var connection = new NpgsqlConnection(_postgres.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            $"""
            INSERT INTO clients (id, tenant_id, client_id, name, type, token_endpoint_auth_method,
                allowed_grant_types, allowed_scopes, redirect_uris, allowed_audiences, require_consent,
                status, created_at)
            VALUES (@id, @tenant, @clientId, 'Raw', @type, @auth, {grantTypes}, ARRAY['a']::text[],
                ARRAY[]::text[], {audiences}, false, 'active', now())
            """,
            connection);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("clientId", clientId);
        command.Parameters.AddWithValue("type", type);
        command.Parameters.AddWithValue("auth", authMethod);

        try
        {
            await command.ExecuteNonQueryAsync();
            return null;
        }
        catch (PostgresException e)
        {
            return e.SqlState;
        }
    }

    [DockerFact]
    public async Task Valid_raw_client_is_accepted()
    {
        var tenantId = await NewTenantAsync();

        var error = await InsertClientRawAsync(
            tenantId, "confidential", "client_secret_basic",
            "ARRAY['client_credentials']::text[]", "ARRAY['https://api.example.com']::text[]");

        Assert.Null(error);
    }

    [DockerFact]
    public async Task Public_client_with_a_secret_method_is_refused()
    {
        var tenantId = await NewTenantAsync();

        var error = await InsertClientRawAsync(
            tenantId, "public", "client_secret_basic",
            "ARRAY['authorization_code']::text[]", "ARRAY[]::text[]");

        Assert.Equal(CheckViolation, error);
    }

    [DockerFact]
    public async Task Client_credentials_for_a_public_client_is_refused()
    {
        var tenantId = await NewTenantAsync();

        var error = await InsertClientRawAsync(
            tenantId, "public", "none",
            "ARRAY['client_credentials']::text[]", "ARRAY['https://api.example.com']::text[]");

        Assert.Equal(CheckViolation, error);
    }

    [DockerFact]
    public async Task Client_credentials_without_an_audience_is_refused()
    {
        var tenantId = await NewTenantAsync();

        var error = await InsertClientRawAsync(
            tenantId, "confidential", "client_secret_basic",
            "ARRAY['client_credentials']::text[]", "ARRAY[]::text[]");

        Assert.Equal(CheckViolation, error);
    }

    [DockerFact]
    public async Task Unknown_grant_type_is_refused()
    {
        var tenantId = await NewTenantAsync();

        var error = await InsertClientRawAsync(
            tenantId, "confidential", "client_secret_basic",
            "ARRAY['password']::text[]", "ARRAY[]::text[]");

        Assert.Equal(CheckViolation, error);
    }

    [DockerFact]
    public async Task Same_client_id_twice_in_one_tenant_is_refused()
    {
        var tenantId = await NewTenantAsync();
        const string grants = "ARRAY['client_credentials']::text[]";
        const string audiences = "ARRAY['https://api.example.com']::text[]";

        Assert.Null(await InsertClientRawAsync(tenantId, "confidential", "client_secret_basic", grants, audiences, "dup"));
        Assert.Equal(
            UniqueViolation,
            await InsertClientRawAsync(tenantId, "confidential", "client_secret_basic", grants, audiences, "dup"));
    }

    [DockerFact]
    public async Task Same_client_id_in_two_tenants_is_allowed()
    {
        var first = await NewTenantAsync();
        var second = await NewTenantAsync();
        const string grants = "ARRAY['client_credentials']::text[]";
        const string audiences = "ARRAY['https://api.example.com']::text[]";

        Assert.Null(await InsertClientRawAsync(first, "confidential", "client_secret_basic", grants, audiences, "shared"));
        Assert.Null(await InsertClientRawAsync(second, "confidential", "client_secret_basic", grants, audiences, "shared"));
    }

    [DockerFact]
    public async Task Secret_cannot_point_to_a_client_of_another_tenant()
    {
        await using var services = _postgres.CreateServices();
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var tenant = TestData.NewTenant();
        var other = TestData.NewTenant();
        var client = TestData.NewServiceClient(tenant.Id);
        db.Tenants.AddRange(tenant, other);
        db.Clients.Add(client);
        await db.SaveChangesAsync();

        var secret = TestData.Secret(client, "value");
        secret.TenantId = other.Id;
        db.ClientSecrets.Add(secret);

        var exception = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(ForeignKeyViolation, Assert.IsType<PostgresException>(exception.InnerException).SqlState);
    }

    [DockerFact]
    public async Task Second_active_key_for_a_tenant_is_refused()
    {
        await using var services = _postgres.CreateServices();
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var tenant = TestData.NewTenant();
        db.Tenants.Add(tenant);

        var first = SigningKey.Create(Guid.CreateVersion7(), tenant.Id, "k1", "{}", "file:k1", TimeSpan.FromHours(1), TestData.Now);
        var second = SigningKey.Create(Guid.CreateVersion7(), tenant.Id, "k2", "{}", "file:k2", TimeSpan.FromHours(1), TestData.Now);
        SigningKeyRotation.ActivateFirst(first, TestData.Now.AddHours(1));
        SigningKeyRotation.ActivateFirst(second, TestData.Now.AddHours(1));
        db.SigningKeys.AddRange(first, second);

        var exception = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(UniqueViolation, Assert.IsType<PostgresException>(exception.InnerException).SqlState);
    }

    [DockerFact]
    public async Task Private_key_material_in_the_reference_is_refused()
    {
        var tenantId = await NewTenantAsync();
        await using var connection = new NpgsqlConnection(_postgres.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO signing_keys (id, tenant_id, kid, public_jwk, private_key_ref, status, published_at, signing_from)
            VALUES (@id, @tenant, 'k1', '{}', '-----BEGIN PRIVATE KEY-----', 'pending', now(), now())
            """,
            connection);
        command.Parameters.AddWithValue("id", Guid.CreateVersion7());
        command.Parameters.AddWithValue("tenant", tenantId);

        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());
        Assert.Equal(CheckViolation, exception.SqlState);
    }
}
