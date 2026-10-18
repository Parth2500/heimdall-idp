using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPurgeIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "ix_token_families_idle_expires_at",
                table: "token_families",
                column: "idle_expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_token_families_revoked_at",
                table: "token_families",
                column: "revoked_at",
                filter: "revoked_at IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_sessions_absolute_expires_at",
                table: "sessions",
                column: "absolute_expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_sessions_revoked_at",
                table: "sessions",
                column: "revoked_at",
                filter: "revoked_at IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_codes_expires_at",
                table: "authorization_codes",
                column: "expires_at",
                filter: "family_id IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_token_families_idle_expires_at",
                table: "token_families");

            migrationBuilder.DropIndex(
                name: "ix_token_families_revoked_at",
                table: "token_families");

            migrationBuilder.DropIndex(
                name: "ix_sessions_absolute_expires_at",
                table: "sessions");

            migrationBuilder.DropIndex(
                name: "ix_sessions_revoked_at",
                table: "sessions");

            migrationBuilder.DropIndex(
                name: "ix_authorization_codes_expires_at",
                table: "authorization_codes");
        }
    }
}
