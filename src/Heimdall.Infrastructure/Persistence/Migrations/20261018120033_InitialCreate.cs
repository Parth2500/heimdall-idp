using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_events",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: true),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    correlation_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    source_ip = table.Column<IPAddress>(type: "inet", nullable: true),
                    actor_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    subject_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    client_pk = table.Column<Guid>(type: "uuid", nullable: true),
                    family_id = table.Column<Guid>(type: "uuid", nullable: true),
                    data = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_events", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "tenants",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    host = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    session_idle_seconds = table.Column<int>(type: "integer", nullable: false),
                    session_absolute_seconds = table.Column<int>(type: "integer", nullable: false),
                    access_token_seconds = table.Column<int>(type: "integer", nullable: false),
                    refresh_idle_seconds = table.Column<int>(type: "integer", nullable: false),
                    refresh_absolute_seconds = table.Column<int>(type: "integer", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tenants", x => x.id);
                    table.CheckConstraint("ck_tenants_lifetimes", "session_idle_seconds BETWEEN 1 AND 34560000 AND session_absolute_seconds BETWEEN 1 AND 34560000 AND access_token_seconds BETWEEN 1 AND 34560000 AND refresh_idle_seconds BETWEEN 1 AND 34560000 AND refresh_absolute_seconds BETWEEN 1 AND 34560000");
                    table.CheckConstraint("ck_tenants_status", "status IN ('active', 'suspended')");
                });

            migrationBuilder.CreateTable(
                name: "clients",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    token_endpoint_auth_method = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    allowed_grant_types = table.Column<string[]>(type: "text[]", nullable: false),
                    allowed_scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    redirect_uris = table.Column<string[]>(type: "text[]", nullable: false),
                    allowed_audiences = table.Column<string[]>(type: "text[]", nullable: false),
                    require_consent = table.Column<bool>(type: "boolean", nullable: false),
                    access_token_seconds = table.Column<int>(type: "integer", nullable: true),
                    refresh_idle_seconds = table.Column<int>(type: "integer", nullable: true),
                    refresh_absolute_seconds = table.Column<int>(type: "integer", nullable: true),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_clients", x => x.id);
                    table.UniqueConstraint("ak_clients_tenant_id_id", x => new { x.tenant_id, x.id });
                    table.CheckConstraint("ck_clients_auth_method", "(type = 'public' AND token_endpoint_auth_method = 'none') OR (type = 'confidential' AND token_endpoint_auth_method = 'client_secret_basic')");
                    table.CheckConstraint("ck_clients_client_credentials_audience", "NOT ('client_credentials' = ANY (allowed_grant_types)) OR cardinality(allowed_audiences) > 0");
                    table.CheckConstraint("ck_clients_client_credentials_confidential", "NOT ('client_credentials' = ANY (allowed_grant_types)) OR type = 'confidential'");
                    table.CheckConstraint("ck_clients_grant_types", "cardinality(allowed_grant_types) > 0 AND allowed_grant_types <@ ARRAY['authorization_code', 'client_credentials', 'refresh_token']::text[]");
                    table.CheckConstraint("ck_clients_lifetimes", "(access_token_seconds IS NULL OR access_token_seconds BETWEEN 1 AND 34560000) AND (refresh_idle_seconds IS NULL OR refresh_idle_seconds BETWEEN 1 AND 34560000) AND (refresh_absolute_seconds IS NULL OR refresh_absolute_seconds BETWEEN 1 AND 34560000)");
                    table.CheckConstraint("ck_clients_status", "status IN ('pending', 'active', 'disabled')");
                    table.CheckConstraint("ck_clients_type", "type IN ('public', 'confidential')");
                    table.ForeignKey(
                        name: "fk_clients_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "signing_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    kid = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    public_jwk = table.Column<string>(type: "jsonb", nullable: false),
                    private_key_ref = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    published_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    signing_from = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    retired_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    remove_after = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    algorithm = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false, defaultValue: "RS256")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_signing_keys", x => x.id);
                    table.CheckConstraint("ck_signing_keys_algorithm", "algorithm = 'RS256'");
                    table.CheckConstraint("ck_signing_keys_private_ref", "private_key_ref NOT ILIKE '%PRIVATE KEY%'");
                    table.CheckConstraint("ck_signing_keys_status", "status IN ('pending', 'active', 'retired')");
                    table.ForeignKey(
                        name: "fk_signing_keys_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "client_secrets",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_pk = table.Column<Guid>(type: "uuid", nullable: false),
                    secret_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_secrets", x => x.id);
                    table.CheckConstraint("ck_client_secrets_hash_length", "octet_length(secret_hash) = 32");
                    table.ForeignKey(
                        name: "fk_client_secrets_clients_tenant_id_client_pk",
                        columns: x => new { x.tenant_id, x.client_pk },
                        principalTable: "clients",
                        principalColumns: new[] { "tenant_id", "id" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_family_id",
                table: "audit_events",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_tenant_id_occurred_at",
                table: "audit_events",
                columns: new[] { "tenant_id", "occurred_at" });

            migrationBuilder.CreateIndex(
                name: "ix_client_secrets_tenant_id_client_pk",
                table: "client_secrets",
                columns: new[] { "tenant_id", "client_pk" });

            migrationBuilder.CreateIndex(
                name: "ix_clients_tenant_id_client_id",
                table: "clients",
                columns: new[] { "tenant_id", "client_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_signing_keys_tenant_id_kid",
                table: "signing_keys",
                columns: new[] { "tenant_id", "kid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_signing_keys_one_active",
                table: "signing_keys",
                column: "tenant_id",
                unique: true,
                filter: "status = 'active'");

            migrationBuilder.CreateIndex(
                name: "ix_tenants_host",
                table: "tenants",
                column: "host",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_events");

            migrationBuilder.DropTable(
                name: "client_secrets");

            migrationBuilder.DropTable(
                name: "signing_keys");

            migrationBuilder.DropTable(
                name: "clients");

            migrationBuilder.DropTable(
                name: "tenants");
        }
    }
}
