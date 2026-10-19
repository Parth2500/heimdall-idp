# Heimdall: Custom OAuth 2.1 / OIDC Identity Provider

Portfolio project aimed at FAANG-level rigor. It will also be reused as the auth provider for my other projects.
Stack: .NET 10 (LTS), PostgreSQL, EF Core, Clean Architecture. Later: Angular for all UI (login, consent and logout pages, admin portal, demo SPA client). Decided 2026-10-18; it replaces React/Next.js.

## How I want you to work with me (important)
- **Claude writes the implementation** (changed on 2026-10-18; before that I wrote it myself). Work in small, tested steps that follow the roadmap order. Do not skip ahead.
- Each step: write the code, write its tests, run `dotnet test`, then explain the *why* of each security decision so I can defend it.
- I should be able to answer interview questions about every choice (e.g. "why DPoP over plain PKCE?").
- Be precise with security language. Flag anything sloppy, including in my own notes.
- Commit only when I ask or approve. Ask before changing a decision that is recorded in the docs.

## Writing rules for docs (ASD-STE100 style, applied by hand, not certified)
- One idea per sentence. Procedure sentences: 20 words or fewer. Descriptions: 25 words or fewer.
- Use the active voice. Name the actor ("The server revokes the family").
- Use one term for one concept. Define each term in the glossary in `docs/threat-model.md`. Do not add synonyms.
- Keep RFC terms and error codes exactly as the RFC writes them (`invalid_grant`, "bearer", "confused deputy").
- No idioms. Avoid "-ing" chains and stacked noun phrases.
- Use American spelling.
- In tables, write short full sentences in the mitigation column, not fragments.
- Claude may update any file, including text the user wrote, when the change is true. Claude still asks before it changes a recorded decision.

## Performance and abuse principles
- Heimdall is a login API. It is slow on purpose where it must be (Argon2id), and it checks everything before it lets a user in. It is **not** designed for 1M req/s on login or `/token`.
- High request volume applies to JWKS, discovery, and offline token checks at resource servers. Those need a cache or a CDN, not extra code paths.
- Write code that scales out: stateless servers, async I/O, no database call on hot read paths (cache client config and keys with explicit invalidation), hot-path SQL as single atomic statements.
- Reject bad traffic cheaply, before the database and before Argon2id.
- Throttle failed attempts. Do not hard-lock accounts, because a lock lets an attacker deny service to a victim. Layered abuse controls (per-IP, per-account backoff, challenge, temporary IP block) are a Phase 2 item.
- Measure before tuning. Set numeric targets after the first k6 run (Phase 4).

## Project layout
```
src/Heimdall.Domain          entities, no dependencies
src/Heimdall.Application     use cases, interfaces (refs Domain)
src/Heimdall.Infrastructure  EF Core, Postgres, key storage (refs Application)
src/Heimdall.Api             endpoints, composition root (refs Application + Infrastructure)
tests/Heimdall.UnitTests          no database
tests/Heimdall.IntegrationTests   PostgreSQL via Testcontainers; skipped without Docker, required in CI
docs/threat-model.md         Phase 0 deliverable
docs/schema-design.md        Phase 0 deliverable (schema, atomic SQL, constraints)
docs/domain-model.md         Rules that each Domain entity enforces. Update it with each Domain change.
docs/diagrams/               Mermaid diagrams. Update them in the same commit as a design change.
```
Dependencies point inward only. Domain must never import EF Core.

## Decisions so far
- Name: Heimdall. Repo `heimdall-idp`, namespaces `Heimdall.*`.
- Depth (security rigor) and breadth (features) both matter, phased over time.
- Time is not a constraint; learning is the goal.
- Deployment target undecided (Azure is an option, which would double as AZ-204 practice: Key Vault for signing keys, Container Apps, managed Postgres). Stay cloud-agnostic until decided.

## Roadmap
**Phase 0, Threat model and design docs (done).**
STRIDE per trust boundary for every endpoint, login and sessions, and tenants. Decisions D1 to D22. Key results: a code is redeemed by one atomic conditional `UPDATE` with a unique index on the hash; refresh token reuse revokes the family at once (no grace window); JWKS is served from memory and a cache, never one database read for each request.

**Phase 1, Core engine (done on 2026-10-19).**
Auth Code + PKCE (S256 mandatory for ALL clients, per OAuth 2.1), RS256 signing with key rotation and an overlap window (old `kid` stays in JWKS until outstanding tokens expire), refresh rotation with family-based theft detection, Argon2id, structured logging with correlation IDs from day one.

**Phase 2, Hardening.**
DPoP (RFC 9449), PAR (RFC 9126), rate limiting on `/authorize`, `/token` and login, introspection (RFC 7662), run the OpenID Foundation conformance suite and fix failures.

**Phase 3, Breadth.**
Multi-tenancy features (portal, onboarding; the `Tenant` table and `TenantId` columns exist from the first migration, see D15-D21 in the threat model), WebAuthn/passkeys, admin portal with RBAC and an immutable audit log, persisted and revocable per-client/per-scope consent.

**Phase 4, Ops.**
Docker Compose for local dev (Postgres done), GitHub Actions CI (build and test done; conformance to add), Terraform/Bicep, k6 load tests on the token endpoint.

## Spec corrections to the original draft
- Code reuse must revoke the **token family derived from that code** and raise an alert. The draft's "invalidates active sessions for that user/client pair" was vague and wrong-shaped.
- Follow RFC 9700 (OAuth Security BCP): no implicit flow, exact-match redirect URIs only, no wildcards.
- Prefer Key Vault or KMS for signing keys over home-rolled encryption at rest, when deploying.

## Data model
The current design is in `docs/schema-design.md` and `docs/domain-model.md`. Changes from the first draft: `SecurityKey` became `SigningKey` (one set for each tenant), `ReplacedByTokenHash` became the foreign key `replaced_by_id`, and the family is its own table (`token_families`). The unique index on the code hash is in the schema (with `tenant_id`).

## Endpoints in scope
`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `GET /oauth/v1/authorize`, `POST /oauth/v1/token`, `GET /oauth/v1/userinfo`, `POST /oauth/v1/revoke`.
Grants: Authorization Code + PKCE, Client Credentials, Refresh Token.

## STRIDE worked example: `/oauth/v1/authorize`
See `docs/threat-model.md`.

## Current state / next steps
1. Done: Phase 0. Threat model (all endpoints, login, tenants), schema design, diagrams.
2. Done: repository files (README, SECURITY, CI, Dependabot, global.json). Remote: github.com/Parth2500/heimdall-idp.
3. Done: Domain layer, all entities, see `docs/domain-model.md`.
4. Done: Application layer for `client_credentials` (`ClientAuthenticator`, platform limits D16, audiences D22, `ClientCredentialsGrant`, `ITokenSigner`, `IAuditLog`). `TimeProvider` is the clock.
5. Done: Infrastructure and Phase 1. Done: EF Core mapping and the first migration (tenants, clients, client_secrets, signing_keys, audit_events), tenant query filter, `EfClientStore`, `EfAuditLog`, dev seed (`dotnet run --project src/Heimdall.Api -- seed-dev`), integration tests. Done: JWT signing (`IKeyMaterialStore`, `DevelopmentKeyFile`, `SigningKeyCache`, `JwtTokenSigner`, `SigningKeyService` for key creation and first activation). Done: Api endpoints `POST /oauth/v1/token` (`client_credentials`), discovery, JWKS; tenant resolution by host; correlation IDs; key activation job; `status` as a concurrency token. Done: key rotation (`SigningKeyService.MaintainAsync`, `SigningKeyJob`, one pending key for each tenant, `remove-key` command). In progress: Authorization Code + PKCE, in steps: (1) users and Argon2id (done: `users` table, `Argon2idPasswordHasher` via libsodium/Sodium.Core, `UserAuthenticator`, `PasswordPolicy`); (2) login sessions and the login API (done: `sessions` table, `SessionService`, `/session/v1` endpoints with antiforgery, Origin check, and JSON-only bodies, security headers); (3) `/authorize` (done: `AuthorizationService`, stored requests, resume, codes issued as hashes; consent page path only, persisted consent is Phase 3); (4) codes and atomic redemption at `/token` (done: `AuthorizationCodeGrant`, `token_families`, `refresh_tokens`, ID tokens, reuse revokes the family, concurrency test); (5) refresh rotation (done: `RefreshTokenGrant`, one conditional statement with the family bindings, reuse revokes the family with no grace window). Phase 1 follow-ups: (6) `/revoke` (done: `TokenRevocation`, the form rules shared with `/token`, a foreign token gets 200 and changes nothing); (7) `/userinfo` (done: `UserInfoService`, `AccessTokenValidator` from the in-memory keys, the userinfo endpoint is an audience of user grants, D22); (8) the consent API (done: `ConsentService`, `/session/v1/consent`, a decision for one stored request and one user; persisted consent is Phase 3); (9) the purge job (done: `DataPurger`, `PurgeJob`, batches with `SKIP LOCKED`, purge indexes); (10) row-level security (done: policies on the nine tenant-owned tables, `TenantConnectionInterceptor`, `heimdall_app` and `heimdall_platform` roles, `PlatformDbContextFactory`, the audit log is append-only for the application). Phase 1 is done. Phase 2 work follows the GitHub issues (board: github.com/users/Parth2500/projects/1). Done: #6 client config cache (`ClientCache`, one query for each tenant, the scoped `EfClientStore` serves only the request's tenant); #7 OpenTelemetry (traces and metrics, OTLP only when configured, `HeimdallMetrics` with fixed tag values, `url.query` removed from spans); #8 health endpoints (`/health/live`, `/health/ready`, before tenant resolution, optional management port). Later: the `consents` table (Phase 3).
6. Local tooling: SDK 10.0.402 (`global.json`). On Linux, integration tests run on rootless Podman (see README).
