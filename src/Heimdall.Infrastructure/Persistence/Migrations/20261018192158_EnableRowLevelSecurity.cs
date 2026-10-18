using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Heimdall.Infrastructure.Persistence.Migrations
{
    /// <summary>
    /// D20, second layer: PostgreSQL row-level security on every tenant-owned table (docs/schema-design.md,
    /// "Row-level security"). The application sets <c>app.tenant_id</c> on each connection open. A row is visible and
    /// writable only when its <c>tenant_id</c> equals that value. Without a value, no row matches (fail closed).
    /// Members of <c>heimdall_platform</c> see every row, for platform jobs only.
    /// </summary>
    public partial class EnableRowLevelSecurity : Migration
    {
        private static readonly string[] TenantTables =
        [
            "users", "sessions", "authorization_requests", "authorization_codes", "token_families", "refresh_tokens",
            "clients", "client_secrets", "signing_keys",
        ];

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Group roles. They cannot log in. An operator grants them to the login roles of each environment.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'heimdall_app') THEN
                        CREATE ROLE heimdall_app NOLOGIN;
                    END IF;
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'heimdall_platform') THEN
                        CREATE ROLE heimdall_platform NOLOGIN;
                    END IF;
                END
                $$;
                """);

            migrationBuilder.Sql("GRANT USAGE ON SCHEMA public TO heimdall_app, heimdall_platform;");
            migrationBuilder.Sql("GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO heimdall_app, heimdall_platform;");
            foreach (var table in TenantTables)
            {
                migrationBuilder.Sql($"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO heimdall_app, heimdall_platform;");
            }

            // The audit log is append-only for the application: no UPDATE and no DELETE.
            migrationBuilder.Sql("GRANT SELECT, INSERT ON audit_events TO heimdall_app, heimdall_platform;");

            // NULLIF: an empty value means no tenant. The cast then gives NULL, and NULL equals nothing.
            const string CurrentTenant = "NULLIF(current_setting('app.tenant_id', true), '')::uuid";
            foreach (var table in TenantTables)
            {
                migrationBuilder.Sql($"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;");

                // FORCE: the table owner is bound by the policies too. A superuser still bypasses them.
                migrationBuilder.Sql($"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;");
                migrationBuilder.Sql(
                    $"CREATE POLICY tenant_isolation ON {table} USING (tenant_id = {CurrentTenant}) WITH CHECK (tenant_id = {CurrentTenant});");
                migrationBuilder.Sql(
                    $"CREATE POLICY platform_access ON {table} TO heimdall_platform USING (true) WITH CHECK (true);");
            }
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            foreach (var table in TenantTables)
            {
                migrationBuilder.Sql($"DROP POLICY IF EXISTS platform_access ON {table};");
                migrationBuilder.Sql($"DROP POLICY IF EXISTS tenant_isolation ON {table};");
                migrationBuilder.Sql($"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;");
                migrationBuilder.Sql($"REVOKE ALL ON {table} FROM heimdall_app, heimdall_platform;");
            }

            migrationBuilder.Sql("REVOKE ALL ON tenants, audit_events FROM heimdall_app, heimdall_platform;");
            migrationBuilder.Sql("REVOKE USAGE ON SCHEMA public FROM heimdall_app, heimdall_platform;");

            // The roles stay: other databases of the cluster can use them, and a login role can still be a member.
        }
    }
}
