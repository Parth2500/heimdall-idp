using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDpopBinding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "dpop_key_thumbprint",
                table: "token_families",
                type: "character varying(43)",
                maxLength: 43,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "require_dpop",
                table: "clients",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddCheckConstraint(
                name: "ck_token_families_dpop_key",
                table: "token_families",
                sql: "dpop_key_thumbprint IS NULL OR length(dpop_key_thumbprint) = 43");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_token_families_dpop_key",
                table: "token_families");

            migrationBuilder.DropColumn(
                name: "dpop_key_thumbprint",
                table: "token_families");

            migrationBuilder.DropColumn(
                name: "require_dpop",
                table: "clients");
        }
    }
}
