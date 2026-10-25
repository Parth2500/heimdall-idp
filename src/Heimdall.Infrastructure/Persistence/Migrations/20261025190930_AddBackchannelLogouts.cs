using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddBackchannelLogouts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "backchannel_logouts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_pk = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    sid = table.Column<string>(type: "character(22)", fixedLength: true, maxLength: 22, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_backchannel_logouts", x => x.id);
                    table.CheckConstraint("ck_backchannel_logouts_attempts", "attempts >= 0");
                    table.CheckConstraint("ck_backchannel_logouts_sid", "length(sid) = 22");
                    table.ForeignKey(
                        name: "fk_backchannel_logouts_clients_tenant_id_client_pk",
                        columns: x => new { x.tenant_id, x.client_pk },
                        principalTable: "clients",
                        principalColumns: new[] { "tenant_id", "id" },
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_backchannel_logouts_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_backchannel_logouts_created_at",
                table: "backchannel_logouts",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "ix_backchannel_logouts_next_attempt_at",
                table: "backchannel_logouts",
                column: "next_attempt_at");

            migrationBuilder.CreateIndex(
                name: "ix_backchannel_logouts_tenant_id_client_pk",
                table: "backchannel_logouts",
                columns: new[] { "tenant_id", "client_pk" });

            // A tenant-owned table: the same grants and row-level security as the others (EnableRowLevelSecurity).
            migrationBuilder.Sql("GRANT SELECT, INSERT, UPDATE, DELETE ON backchannel_logouts TO heimdall_app, heimdall_platform;");
            migrationBuilder.Sql("ALTER TABLE backchannel_logouts ENABLE ROW LEVEL SECURITY;");
            migrationBuilder.Sql("ALTER TABLE backchannel_logouts FORCE ROW LEVEL SECURITY;");
            migrationBuilder.Sql(
                "CREATE POLICY tenant_isolation ON backchannel_logouts " +
                "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) " +
                "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);");
            migrationBuilder.Sql("CREATE POLICY platform_access ON backchannel_logouts TO heimdall_platform USING (true) WITH CHECK (true);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Dropping the table drops its policies and grants too.
            migrationBuilder.DropTable(
                name: "backchannel_logouts");
        }
    }
}
