using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDpopCodeBinding : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "dpop_key_thumbprint",
                table: "authorization_requests",
                type: "character varying(43)",
                maxLength: 43,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "dpop_key_thumbprint",
                table: "authorization_codes",
                type: "character varying(43)",
                maxLength: 43,
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_authorization_requests_dpop_key",
                table: "authorization_requests",
                sql: "dpop_key_thumbprint IS NULL OR length(dpop_key_thumbprint) = 43");

            migrationBuilder.AddCheckConstraint(
                name: "ck_authorization_codes_dpop_key",
                table: "authorization_codes",
                sql: "dpop_key_thumbprint IS NULL OR length(dpop_key_thumbprint) = 43");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_authorization_requests_dpop_key",
                table: "authorization_requests");

            migrationBuilder.DropCheckConstraint(
                name: "ck_authorization_codes_dpop_key",
                table: "authorization_codes");

            migrationBuilder.DropColumn(
                name: "dpop_key_thumbprint",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "dpop_key_thumbprint",
                table: "authorization_codes");
        }
    }
}
