# Heimdall

Heimdall is a custom OAuth 2.1 and OpenID Connect identity provider. It is a portfolio project built with strong attention to security. The plan is to reuse it as the login service for other projects.

**Status:** early development. Phase 0 (threat model and design) is done. Phase 1 (core engine) is in progress: the Domain layer is done, the Application layer is next. Do not use Heimdall in production.

## Stack

- .NET 10, ASP.NET Core
- PostgreSQL, EF Core
- Clean Architecture (dependencies point inward only)
- Multi-tenant from the first migration

## Repository layout

| Path | Content |
|---|---|
| `src/Heimdall.Domain` | Entities and rules. No dependencies. |
| `src/Heimdall.Application` | Use cases and interfaces. |
| `src/Heimdall.Infrastructure` | EF Core, PostgreSQL, key storage. |
| `src/Heimdall.Api` | Endpoints and composition root. |
| `tests/Heimdall.UnitTests` | Unit tests. No database. |
| `tests/Heimdall.IntegrationTests` | Tests against PostgreSQL in a Testcontainers container. They need Docker. Without Docker they are skipped, except in CI, where they must run. |
| `docs/` | Threat model, schema design, diagrams. |

## Documents

- [Threat model](docs/threat-model.md): STRIDE for each endpoint and trust boundary, with the security decisions (D1 to D22).
- [Schema design](docs/schema-design.md): tables, constraints, and the atomic SQL statements.
- [Domain model](docs/domain-model.md): the rules that each entity enforces, with references to the decisions.
- [Diagrams](docs/diagrams/README.md): architecture, flows, data model, key rotation.

## Build and test

You need the .NET 10 SDK, feature band 10.0.400 or later. `global.json` pins the version.

```
dotnet build Heimdall.slnx
dotnet test Heimdall.slnx
```

The integration tests start PostgreSQL with Testcontainers. Without Docker, they are skipped. CI requires them.

To use rootless Podman instead of Docker on Linux, start its socket and set two variables:
```
systemctl --user start podman.socket
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
export TESTCONTAINERS_RYUK_DISABLED=true   # Ryuk often fails under rootless Podman
```

## Run locally

You need Docker for PostgreSQL.

1. Start PostgreSQL:
   ```
   cp .env.example .env        # then set POSTGRES_PASSWORD
   docker compose up -d
   ```
2. Give the API the connection string. The password is never in an appsettings file:
   ```
   dotnet user-secrets set "ConnectionStrings:Heimdall" "Host=localhost;Port=5432;Database=heimdall;Username=heimdall;Password=<POSTGRES_PASSWORD>" --project src/Heimdall.Api
   ```
3. Apply the migrations and create the development tenant and client:
   ```
   dotnet run --project src/Heimdall.Api -- seed-dev
   ```
   The command runs only in the Development environment. It prints the client secret once. Heimdall stores only its hash, so save the secret.

   The command also creates the tenant's first signing key in `src/Heimdall.Api/.local/signing-keys.json`, which git ignores. The key waits one JWKS cache lifetime (30 seconds in Development) before it can sign. Run `seed-dev` again after that time to activate it.

To create a migration, use the pinned tool: `dotnet dotnet-ef migrations add <Name> --project src/Heimdall.Infrastructure --startup-project src/Heimdall.Api --output-dir Persistence/Migrations`.

## Roadmap

1. **Phase 0:** threat model and design documents. Done.
2. **Phase 1:** core engine. Authorization code with PKCE, RS256 signing with key rotation, refresh token rotation with family revocation, Argon2id.
3. **Phase 2:** hardening. DPoP, PAR, rate limiting, introspection, OpenID conformance suite.
4. **Phase 3:** breadth. Tenant administration, WebAuthn, admin portal, audit log, consent management.
5. **Phase 4:** operations. CI, infrastructure as code, load tests.

## Security

See [SECURITY.md](SECURITY.md).
