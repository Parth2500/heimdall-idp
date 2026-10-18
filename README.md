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
| `tests/Heimdall.UnitTests` | Unit tests. |
| `docs/` | Threat model, schema design, diagrams. |

## Documents

- [Threat model](docs/threat-model.md): STRIDE for each endpoint and trust boundary, with the security decisions (D1 to D22).
- [Schema design](docs/schema-design.md): tables, constraints, and the atomic SQL statements.
- [Domain model](docs/domain-model.md): the rules that each entity enforces, with references to the decisions.
- [Diagrams](docs/diagrams/README.md): architecture, flows, data model, key rotation.

## Build and test

You need the .NET 10 SDK.

```
dotnet build Heimdall.slnx
dotnet test Heimdall.slnx
```

## Run PostgreSQL for development

```
cp .env.example .env        # then set POSTGRES_PASSWORD
docker compose up -d
```

## Roadmap

1. **Phase 0:** threat model and design documents. Done.
2. **Phase 1:** core engine. Authorization code with PKCE, RS256 signing with key rotation, refresh token rotation with family revocation, Argon2id.
3. **Phase 2:** hardening. DPoP, PAR, rate limiting, introspection, OpenID conformance suite.
4. **Phase 3:** breadth. Tenant administration, WebAuthn, admin portal, audit log, consent management.
5. **Phase 4:** operations. CI, infrastructure as code, load tests.

## Security

See [SECURITY.md](SECURITY.md).
