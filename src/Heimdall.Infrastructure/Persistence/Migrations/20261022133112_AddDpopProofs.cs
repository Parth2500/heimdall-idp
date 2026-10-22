using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDpopProofs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "dpop_proofs",
                columns: table => new
                {
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    proof_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_dpop_proofs", x => new { x.tenant_id, x.proof_hash });
                    table.CheckConstraint("ck_dpop_proofs_hash_length", "octet_length(proof_hash) = 32");
                    table.ForeignKey(
                        name: "fk_dpop_proofs_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_dpop_proofs_expires_at",
                table: "dpop_proofs",
                column: "expires_at");

            // A tenant-owned table: the same grants and row-level security as the others (EnableRowLevelSecurity).
            migrationBuilder.Sql("GRANT SELECT, INSERT, UPDATE, DELETE ON dpop_proofs TO heimdall_app, heimdall_platform;");
            migrationBuilder.Sql("ALTER TABLE dpop_proofs ENABLE ROW LEVEL SECURITY;");
            migrationBuilder.Sql("ALTER TABLE dpop_proofs FORCE ROW LEVEL SECURITY;");
            migrationBuilder.Sql(
                "CREATE POLICY tenant_isolation ON dpop_proofs " +
                "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) " +
                "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);");
            migrationBuilder.Sql("CREATE POLICY platform_access ON dpop_proofs TO heimdall_platform USING (true) WITH CHECK (true);");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Dropping the table drops its policies and grants too.
            migrationBuilder.DropTable(
                name: "dpop_proofs");
        }
    }
}
