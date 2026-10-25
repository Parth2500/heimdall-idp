using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddClientLogoutUris : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "backchannel_logout_uri",
                table: "clients",
                type: "character varying(2048)",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<string[]>(
                name: "post_logout_redirect_uris",
                table: "clients",
                type: "text[]",
                nullable: false,
                defaultValue: new string[0]);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "backchannel_logout_uri",
                table: "clients");

            migrationBuilder.DropColumn(
                name: "post_logout_redirect_uris",
                table: "clients");
        }
    }
}
