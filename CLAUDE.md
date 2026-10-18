# Heimdall: Custom OAuth 2.1 / OIDC Identity Provider

Portfolio project aimed at FAANG-level rigor. It will also be reused as the auth provider for my other projects.
Stack: .NET 10 (LTS), PostgreSQL, EF Core, Clean Architecture. Later: React/Next.js admin portal, demo SPA client.

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
- Text that the user wrote is changed only when the user agrees.

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
tests/Heimdall.UnitTests
docs/threat-model.md         Phase 0 deliverable
docs/schema-design.md        Phase 0 deliverable (schema, atomic SQL, constraints)
```
Dependencies point inward only. Domain must never import EF Core.

## Decisions so far
- Name: Heimdall. Repo `heimdall-idp`, namespaces `Heimdall.*`.
- Depth (security rigor) and breadth (features) both matter, phased over time.
- Time is not a constraint; learning is the goal.
- Deployment target undecided (Azure is an option, which would double as AZ-204 practice: Key Vault for signing keys, Container Apps, managed Postgres). Stay cloud-agnostic until decided.

## Roadmap
**Phase 0, Threat model and design docs (current).**
STRIDE per trust boundary. Worked example for `/oauth/v1/authorize` is done (see below). My homework: fill the STRIDE table for `/oauth/v1/token`, then the refresh flow and JWKS endpoint. Hunt for: concurrent double-submit of the same auth code (needs DB-level locking, e.g. `SELECT ... FOR UPDATE` or a unique constraint), refresh token family reuse (synchronous revocation, no window), JWKS being hammered (cache/CDN, not a DB hit per request).

**Phase 1, Core engine.**
Auth Code + PKCE (S256 mandatory for ALL clients, per OAuth 2.1), RS256 signing with key rotation and an overlap window (old `kid` stays in JWKS until outstanding tokens expire), refresh rotation with family-based theft detection, Argon2id, structured logging with correlation IDs from day one.

**Phase 2, Hardening.**
DPoP (RFC 9449), PAR (RFC 9126), rate limiting on `/authorize`, `/token` and login, introspection (RFC 7662), run the OpenID Foundation conformance suite and fix failures.

**Phase 3, Breadth.**
Multi-tenancy features (portal, onboarding; the `Tenant` table and `TenantId` columns exist from the first migration, see D15-D21 in the threat model), WebAuthn/passkeys, admin portal with RBAC and an immutable audit log, persisted and revocable per-client/per-scope consent.

**Phase 4, Ops.**
Docker Compose for local dev, GitHub Actions CI (build, test, conformance), Terraform/Bicep, k6 load tests on the token endpoint.

## Spec corrections to the original draft
- Code reuse must revoke the **token family derived from that code** and raise an alert. The draft's "invalidates active sessions for that user/client pair" was vague and wrong-shaped.
- Follow RFC 9700 (OAuth Security BCP): no implicit flow, exact-match redirect URIs only, no wildcards.
- Prefer Key Vault or KMS for signing keys over home-rolled encryption at rest, when deploying.

## Original data model (starting point, to be refined)
Entities: User, Client, AuthorizationCode, RefreshToken (with TokenFamilyId, ReplacedByTokenHash), SecurityKey.
Open schema question: `AuthorizationCode.CodeHash` needs a unique index enforced at the DB level, not just in app code. Codes are single-use with a 5-minute TTL and are hashed at rest.

## Endpoints in scope
`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `GET /oauth/v1/authorize`, `POST /oauth/v1/token`, `GET /oauth/v1/userinfo`, `POST /oauth/v1/revoke`.
Grants: Authorization Code + PKCE, Client Credentials, Refresh Token.

## STRIDE worked example: `/oauth/v1/authorize`
See `docs/threat-model.md`.

## Current state / next steps
1. Done: solution scaffolded and builds; .gitignore, .editorconfig, docker-compose.yml (Postgres), Directory.Build.props, stub docs/threat-model.md.
2. `/token`, refresh and JWKS STRIDE tables drafted (Claude wrote them at my request; I must read and be able to defend each row). Next: I review them, then `/revoke` and `/userinfo`, then design the EF Core schema.
