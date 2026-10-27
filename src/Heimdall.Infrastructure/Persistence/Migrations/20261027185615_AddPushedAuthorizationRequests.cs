using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPushedAuthorizationRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_authorization_requests_tenant_id",
                table: "authorization_requests");

            migrationBuilder.AddColumn<bool>(
                name: "require_pushed_authorization_requests",
                table: "clients",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "prompt_none",
                table: "authorization_requests",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<byte[]>(
                name: "request_uri_hash",
                table: "authorization_requests",
                type: "bytea",
                maxLength: 32,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_authorization_requests_tenant_id_request_uri_hash",
                table: "authorization_requests",
                columns: new[] { "tenant_id", "request_uri_hash" },
                unique: true,
                filter: "request_uri_hash IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_authorization_requests_tenant_id_request_uri_hash",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "require_pushed_authorization_requests",
                table: "clients");

            migrationBuilder.DropColumn(
                name: "prompt_none",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "request_uri_hash",
                table: "authorization_requests");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_requests_tenant_id",
                table: "authorization_requests",
                column: "tenant_id");
        }
    }
}
