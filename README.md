# Heimdall

Heimdall is a custom OAuth 2.1 and OpenID Connect identity provider. It is a portfolio project built with strong attention to security. The plan is to reuse it as the login service for other projects.

**Status:** early development. Phase 0 (threat model and design) is done. Phase 1 (core engine) is feature-complete: authorization code with PKCE, client credentials, refresh token rotation with family revocation, RS256 key rotation, and Argon2id. `/userinfo`, `/revoke`, consent, and row-level security come next. Do not use Heimdall in production.

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
| `docs/` | Client integration guide, threat model, schema design, diagrams. |

## Documents

- [Client documentation](docs/documentation.md): how to connect an application or API to Heimdall. Start here if you integrate with Heimdall.
- [Threat model](docs/threat-model.md): STRIDE for each endpoint and trust boundary, with the security decisions (D1 to D23).
- [Schema design](docs/schema-design.md): tables, constraints, and the atomic SQL statements.
- [Domain model](docs/domain-model.md): the rules that each entity enforces, with references to the decisions.
- [Front-end design](docs/frontend-design.md): the Angular account pages and the demo SPA (decisions U1 to U14, proposed).
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

### Property tests

The tests in `tests/Heimdall.UnitTests/Properties` use CsCheck. Each test states a rule for every input, and CsCheck tries thousands of generated inputs against it. The parsers of client input must refuse bad input without an exception.

Each run uses new random inputs. A failure prints a seed. To run the same inputs again, set the seed:
```
CsCheck_Seed=<seed> dotnet test tests/Heimdall.UnitTests --filter "FullyQualifiedName~Properties"
```
Add each failure as an example test too, so that it stays tested.

### Mutation testing

Stryker.NET is a local tool. It mutates one project and runs the unit tests against each mutant.
```
dotnet tool restore
cd tests/Heimdall.UnitTests
dotnet stryker --project Heimdall.Domain.csproj
dotnet stryker --project Heimdall.Application.csproj
dotnet stryker --project Heimdall.Infrastructure.csproj -m "**/Keys/AccessTokenValidator.cs"
dotnet stryker --project Heimdall.Api.csproj -m "**/Endpoints/OAuthFormReader.cs"
```

In Infrastructure and Api, only the token validator and the form reader have unit tests. The integration tests cover the rest.

A surviving mutant shows a rule that no test checks. Write a test that kills it.
Some mutants change only the timing or the text, and no test can detect them. Mark each one in the code with `// Stryker disable once <mutator> : <reason>`.
A marker disables every variant of that mutator on the line. When a marker would also hide a mutant that a test kills, change the code instead.
When Stryker logs "Safe Mode", it skipped every mutant of a method, because one mutant did not compile. An `out` variable that is read after a `||` chain is the usual cause. Change the code so that Stryker can test the method.
`stryker-config.json` ignores three groups of mutants:
- Argument guards and exception constructors.
- `ConfigureAwait`. The test host has no synchronization context.
- The audit detail of `OAuthError`. The client sees only the error code (D5).

The configuration also excludes `DependencyInjection.cs`. The integration tests cover the service wiring.
The unit tests use in-memory fakes for the stores. `InMemoryTokenStore` has the same conditions as each SQL statement in `EfTokenStore`, and a rollback undoes its changes. The integration tests check the SQL itself.

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

   The command also creates the development user `alice@acme.localhost` and prints its password once. It also creates the tenant's first signing key in `src/Heimdall.Api/.local/signing-keys.json`, which git ignores.

4. Start the server and request a token. The running server activates the signing key when its wait ends (35 seconds in Development):
   ```
   dotnet run --project src/Heimdall.Api --launch-profile https
   curl -k --resolve acme.localhost:7200:127.0.0.1 https://acme.localhost:7200/.well-known/openid-configuration
   curl -k --resolve acme.localhost:7200:127.0.0.1 -u "demo-service:<client_secret>" \
        -d grant_type=client_credentials https://acme.localhost:7200/oauth/v1/token
   ```
   Heimdall finds the tenant from the host name, so the request must use `acme.localhost`. It refuses plain HTTP.

   The login API for the future Angular page is under `/session/v1` (`csrf`, `login`, `logout`, `me`, `consent`). It needs the antiforgery header, so test it with the integration tests, not plain `curl`.

   The local `heimdall` database user is a superuser, so it bypasses row-level security. The integration tests use restricted logins instead. To run locally with the same restriction, create the logins once, then use them in `ConnectionStrings:Heimdall` and `ConnectionStrings:HeimdallPlatform`. Keep the superuser for migrations and `seed-dev`.
   ```sql
   CREATE ROLE heimdall_app_login LOGIN PASSWORD '<password>' IN ROLE heimdall_app;
   CREATE ROLE heimdall_platform_login LOGIN PASSWORD '<password>' IN ROLE heimdall_platform;
   ```

## Operations

Emergency removal of a stolen signing key (see `docs/threat-model.md`, JWKS):
```
dotnet run --project src/Heimdall.Api -- remove-key <tenant host> <kid>
```
The key leaves the JWKS at once, and tokens it signed stop working. Token issuance stops until the replacement key is active, at most one publish wait.

Telemetry: set `OTEL_EXPORTER_OTLP_ENDPOINT` (for example `http://localhost:4317`) to send OpenTelemetry traces and metrics to a collector. Without it, Heimdall sends nothing. Heimdall's own metrics are in the meter `Heimdall` (`heimdall.token.requests`, `heimdall.login.attempts`, `heimdall.password_hash.*`, `heimdall.security.alerts`, `heimdall.cache.lookups`).

Behind a reverse proxy, list the proxy addresses in `Heimdall:ForwardedHeaders:KnownProxies` (or CIDR ranges in `KnownNetworks`). The proxy must keep the original Host header and set `X-Forwarded-For` and `X-Forwarded-Proto`. Without this setting, Heimdall ignores forwarded headers.

Rate limits are in `Heimdall:RateLimits` (`Login`, `Authorize`, `ClientFailures`, `ClientIssuance`, each with `PermitLimit` and `Window`). The counters are per server.

Health probes: `/health/live` (the process answers) and `/health/ready` (the database answers). Set `Heimdall:Health:Port` to a management port in each deployment, so the probes answer only there.

To create a migration, use the pinned tool: `dotnet dotnet-ef migrations add <Name> --project src/Heimdall.Infrastructure --startup-project src/Heimdall.Api --output-dir Persistence/Migrations`.

## Supply chain checks

- NuGet audit runs at each restore (`Directory.Build.props`). A known-vulnerable package, direct or transitive, fails the build, on a developer machine and in CI.
- CI pins each GitHub Action to a full commit SHA. A moved or hijacked tag cannot change the code that runs. Dependabot updates the pins.
- CodeQL scans the C# code with the `security-extended` queries on each push, each pull request, and once a week.
- Dependency review fails a pull request that adds a dependency with a known vulnerability.
- GitHub secret scanning with push protection, Dependabot alerts, and Dependabot security updates are on for the repository.

## Roadmap

1. **Phase 0:** threat model and design documents. Done.
2. **Phase 1:** core engine. Authorization code with PKCE, RS256 signing with key rotation, refresh token rotation with family revocation, Argon2id, `/userinfo`, `/revoke`, the consent API, the purge job, and row-level security. Done.
3. **Phase 2:** hardening. DPoP, PAR, rate limiting, introspection, RP-initiated logout, OpenID conformance suite.
4. **Phase 3:** breadth. Tenant administration, WebAuthn, admin portal, audit log, consent management. Client libraries like Microsoft's: an account picker, a browser library with redirect and popup sign-in, and a .NET package for APIs.
5. **Phase 4:** operations. CI, infrastructure as code, load tests.

## Security

See [SECURITY.md](SECURITY.md).
