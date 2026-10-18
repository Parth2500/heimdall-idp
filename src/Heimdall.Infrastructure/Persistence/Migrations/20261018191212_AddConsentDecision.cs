using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddConsentDecision : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "consent_approved",
                table: "authorization_requests",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "consent_user_id",
                table: "authorization_requests",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_authorization_requests_consent",
                table: "authorization_requests",
                sql: "(consent_user_id IS NULL) = (consent_approved IS NULL)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_authorization_requests_consent",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "consent_approved",
                table: "authorization_requests");

            migrationBuilder.DropColumn(
                name: "consent_user_id",
                table: "authorization_requests");
        }
    }
}
