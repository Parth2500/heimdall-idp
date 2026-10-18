using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTokenFamiliesAndRefreshTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "token_families",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_pk = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    source_code_id = table.Column<Guid>(type: "uuid", nullable: false),
                    scope = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    absolute_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    idle_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_reason = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_token_families", x => x.id);
                    table.UniqueConstraint("ak_token_families_tenant_id_id", x => new { x.tenant_id, x.id });
                    table.CheckConstraint("ck_token_families_idle", "idle_expires_at <= absolute_expires_at");
                    table.CheckConstraint("ck_token_families_revoked_reason", "revoked_reason IS NULL OR revoked_reason IN ('reuse_detected', 'user_logout', 'admin', 'user_disabled', 'consent_removed')");
                    table.ForeignKey(
                        name: "fk_token_families_clients_client_pk",
                        column: x => x.client_pk,
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_token_families_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_token_families_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    family_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    replaced_by_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_refresh_tokens", x => x.id);
                    table.ForeignKey(
                        name: "fk_refresh_tokens_refresh_tokens_replaced_by_id",
                        column: x => x.replaced_by_id,
                        principalTable: "refresh_tokens",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_refresh_tokens_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_refresh_tokens_token_families_tenant_id_family_id",
                        columns: x => new { x.tenant_id, x.family_id },
                        principalTable: "token_families",
                        principalColumns: new[] { "tenant_id", "id" },
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_authorization_codes_family_id",
                table: "authorization_codes",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_family_id",
                table: "refresh_tokens",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_replaced_by_id",
                table: "refresh_tokens",
                column: "replaced_by_id");

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_tenant_id_family_id",
                table: "refresh_tokens",
                columns: new[] { "tenant_id", "family_id" });

            migrationBuilder.CreateIndex(
                name: "ix_refresh_tokens_tenant_id_token_hash",
                table: "refresh_tokens",
                columns: new[] { "tenant_id", "token_hash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_token_families_client_pk",
                table: "token_families",
                column: "client_pk");

            migrationBuilder.CreateIndex(
                name: "ix_token_families_user_id",
                table: "token_families",
                column: "user_id");

            migrationBuilder.AddForeignKey(
                name: "fk_authorization_codes_token_families_family_id",
                table: "authorization_codes",
                column: "family_id",
                principalTable: "token_families",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);

            // The code redemption is one UPDATE that sets family_id before the family row is inserted in the same
            // transaction (docs/schema-design.md, "Redeem a code"). PostgreSQL checks this key at commit instead.
            migrationBuilder.Sql(
                "ALTER TABLE authorization_codes ALTER CONSTRAINT fk_authorization_codes_token_families_family_id DEFERRABLE INITIALLY DEFERRED;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_authorization_codes_token_families_family_id",
                table: "authorization_codes");

            migrationBuilder.DropTable(
                name: "refresh_tokens");

            migrationBuilder.DropTable(
                name: "token_families");

            migrationBuilder.DropIndex(
                name: "ix_authorization_codes_family_id",
                table: "authorization_codes");
        }
    }
}
