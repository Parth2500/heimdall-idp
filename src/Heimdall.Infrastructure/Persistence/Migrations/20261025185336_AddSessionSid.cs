using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionSid : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "sid",
                table: "token_families",
                type: "character(22)",
                fixedLength: true,
                maxLength: 22,
                nullable: true);

            // An existing session gets its own random sid before the column becomes NOT NULL. A shared default would break
            // the unique index. gen_random_uuid() is built in (no pgcrypto): 16 bytes give 22 base64url characters.
            migrationBuilder.AddColumn<string>(
                name: "sid",
                table: "sessions",
                type: "character(22)",
                fixedLength: true,
                maxLength: 22,
                nullable: true);
            migrationBuilder.Sql(
                "UPDATE sessions SET sid = translate(rtrim(encode(decode(replace(gen_random_uuid()::text, '-', ''), 'hex'), 'base64'), '='), '+/', '-_');");
            migrationBuilder.AlterColumn<string>(
                name: "sid",
                table: "sessions",
                type: "character(22)",
                fixedLength: true,
                maxLength: 22,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character(22)",
                oldFixedLength: true,
                oldMaxLength: 22,
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "sid",
                table: "authorization_codes",
                type: "character(22)",
                fixedLength: true,
                maxLength: 22,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_token_families_tenant_id_sid",
                table: "token_families",
                columns: new[] { "tenant_id", "sid" },
                filter: "sid IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "ck_token_families_sid",
                table: "token_families",
                sql: "sid IS NULL OR length(sid) = 22");

            migrationBuilder.CreateIndex(
                name: "ix_sessions_tenant_id_sid",
                table: "sessions",
                columns: new[] { "tenant_id", "sid" },
                unique: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_sessions_sid",
                table: "sessions",
                sql: "length(sid) = 22");

            migrationBuilder.AddCheckConstraint(
                name: "ck_authorization_codes_sid",
                table: "authorization_codes",
                sql: "sid IS NULL OR length(sid) = 22");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_token_families_tenant_id_sid",
                table: "token_families");

            migrationBuilder.DropCheckConstraint(
                name: "ck_token_families_sid",
                table: "token_families");

            migrationBuilder.DropIndex(
                name: "ix_sessions_tenant_id_sid",
                table: "sessions");

            migrationBuilder.DropCheckConstraint(
                name: "ck_sessions_sid",
                table: "sessions");

            migrationBuilder.DropCheckConstraint(
                name: "ck_authorization_codes_sid",
                table: "authorization_codes");

            migrationBuilder.DropColumn(
                name: "sid",
                table: "token_families");

            migrationBuilder.DropColumn(
                name: "sid",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "sid",
                table: "authorization_codes");
        }
    }
}
