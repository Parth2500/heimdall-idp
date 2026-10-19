using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddLoginThrottles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "login_throttles",
                columns: table => new
                {
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    source_key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    failures = table.Column<int>(type: "integer", nullable: false),
                    last_failure_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    throttled_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_login_throttles", x => new { x.tenant_id, x.user_id, x.source_key });
                    table.CheckConstraint("ck_login_throttles_failures", "failures >= 1");
                    table.ForeignKey(
                        name: "fk_login_throttles_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_login_throttles_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_login_throttles_last_failure_at",
                table: "login_throttles",
                column: "last_failure_at");

            migrationBuilder.CreateIndex(
                name: "ix_login_throttles_user_id",
                table: "login_throttles",
                column: "user_id");

            // A tenant-owned table: the same grants and row-level security as the others (EnableRowLevelSecurity).
            migrationBuilder.Sql("GRANT SELECT, INSERT, UPDATE, DELETE ON login_throttles TO heimdall_app, heimdall_platform;");
            migrationBuilder.Sql("ALTER TABLE login_throttles ENABLE ROW LEVEL SECURITY;");
            migrationBuilder.Sql("ALTER TABLE login_throttles FORCE ROW LEVEL SECURITY;");
            migrationBuilder.Sql(
                "CREATE POLICY tenant_isolation ON login_throttles " +
                "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) " +
                "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);");
            migrationBuilder.Sql("CREATE POLICY platform_access ON login_throttles TO heimdall_platform USING (true) WITH CHECK (true);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "login_throttles");
        }
    }
}
