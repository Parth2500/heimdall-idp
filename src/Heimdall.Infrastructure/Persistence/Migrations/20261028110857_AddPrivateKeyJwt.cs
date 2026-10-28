using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPrivateKeyJwt : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_clients_auth_method",
                table: "clients");

            migrationBuilder.AddColumn<string>(
                name: "jwks",
                table: "clients",
                type: "character varying(16384)",
                maxLength: 16384,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "client_assertions",
                columns: table => new
                {
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    assertion_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_client_assertions", x => new { x.tenant_id, x.assertion_hash });
                    table.CheckConstraint("ck_client_assertions_hash_length", "octet_length(assertion_hash) = 32");
                    table.ForeignKey(
                        name: "fk_client_assertions_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.AddCheckConstraint(
                name: "ck_clients_auth_method",
                table: "clients",
                sql: "(type = 'public' AND token_endpoint_auth_method = 'none') OR (type = 'confidential' AND token_endpoint_auth_method IN ('client_secret_basic', 'private_key_jwt'))");

            migrationBuilder.AddCheckConstraint(
                name: "ck_clients_jwks",
                table: "clients",
                sql: "(token_endpoint_auth_method = 'private_key_jwt') = (jwks IS NOT NULL)");

            migrationBuilder.CreateIndex(
                name: "ix_client_assertions_expires_at",
                table: "client_assertions",
                column: "expires_at");

            // A tenant-owned table: the same grants and row-level security as the others (EnableRowLevelSecurity).
            migrationBuilder.Sql("GRANT SELECT, INSERT, UPDATE, DELETE ON client_assertions TO heimdall_app, heimdall_platform;");
            migrationBuilder.Sql("ALTER TABLE client_assertions ENABLE ROW LEVEL SECURITY;");
            migrationBuilder.Sql("ALTER TABLE client_assertions FORCE ROW LEVEL SECURITY;");
            migrationBuilder.Sql(
                "CREATE POLICY tenant_isolation ON client_assertions " +
                "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) " +
                "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);");
            migrationBuilder.Sql("CREATE POLICY platform_access ON client_assertions TO heimdall_platform USING (true) WITH CHECK (true);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Dropping the table drops its policies and grants too.
            migrationBuilder.DropTable(
                name: "client_assertions");

            migrationBuilder.DropCheckConstraint(
                name: "ck_clients_auth_method",
                table: "clients");

            migrationBuilder.DropCheckConstraint(
                name: "ck_clients_jwks",
                table: "clients");

            migrationBuilder.DropColumn(
                name: "jwks",
                table: "clients");

            migrationBuilder.AddCheckConstraint(
                name: "ck_clients_auth_method",
                table: "clients",
                sql: "(type = 'public' AND token_endpoint_auth_method = 'none') OR (type = 'confidential' AND token_endpoint_auth_method = 'client_secret_basic')");
        }
    }
}
