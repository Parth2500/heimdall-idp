using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthorizationRequestsAndCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "authorization_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_pk = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    code_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    redirect_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    scope = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    code_challenge = table.Column<string>(type: "character(43)", fixedLength: true, maxLength: 43, nullable: false),
                    nonce = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    auth_time = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    redeemed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    family_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_authorization_codes", x => x.id);
                    table.ForeignKey(
                        name: "fk_authorization_codes_clients_client_pk",
                        column: x => x.client_pk,
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_authorization_codes_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_authorization_codes_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "authorization_requests",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_pk = table.Column<Guid>(type: "uuid", nullable: false),
                    redirect_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    scope = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    state = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    nonce = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    code_challenge = table.Column<string>(type: "character(43)", fixedLength: true, maxLength: 43, nullable: false),
                    force_login = table.Column<bool>(type: "boolean", nullable: false),
                    max_age_seconds = table.Column<int>(type: "integer", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_authorization_requests", x => x.id);
                    table.CheckConstraint("ck_authorization_requests_max_age", "max_age_seconds IS NULL OR max_age_seconds >= 0");
                    table.ForeignKey(
                        name: "fk_authorization_requests_clients_client_pk",
                        column: x => x.client_pk,
                        principalTable: "clients",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "fk_authorization_requests_tenants_tenant_id",
                        column: x => x.tenant_id,
                        principalTable: "tenants",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_authorization_codes_client_pk",
                table: "authorization_codes",
                column: "client_pk");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_codes_tenant_id_code_hash",
                table: "authorization_codes",
                columns: new[] { "tenant_id", "code_hash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_authorization_codes_user_id",
                table: "authorization_codes",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_requests_client_pk",
                table: "authorization_requests",
                column: "client_pk");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_requests_expires_at",
                table: "authorization_requests",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_authorization_requests_tenant_id",
                table: "authorization_requests",
                column: "tenant_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authorization_codes");

            migrationBuilder.DropTable(
                name: "authorization_requests");
        }
    }
}
