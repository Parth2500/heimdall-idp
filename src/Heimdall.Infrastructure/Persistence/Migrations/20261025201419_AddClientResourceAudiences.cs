using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddClientResourceAudiences : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string[]>(
                name: "resource_audiences",
                table: "clients",
                type: "text[]",
                nullable: false,
                defaultValue: new string[0]);

            migrationBuilder.AddCheckConstraint(
                name: "ck_clients_resource_audiences_confidential",
                table: "clients",
                sql: "cardinality(resource_audiences) = 0 OR type = 'confidential'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_clients_resource_audiences_confidential",
                table: "clients");

            migrationBuilder.DropColumn(
                name: "resource_audiences",
                table: "clients");
        }
    }
}
