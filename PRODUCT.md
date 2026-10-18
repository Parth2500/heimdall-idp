# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

- Backend: .NET 10, ASP.NET Core, PostgreSQL, EF Core, Clean Architecture.
- UI: Angular for every surface. This includes the login, consent and logout pages, the admin portal and the demo SPA client. The user decided this on 2026-10-18. It replaces the earlier React/Next.js plan.
- Deployment target: undecided. Azure is an option. Stay cloud-agnostic.

## Users

All three audiences will use Heimdall. When their needs conflict, favor them in this order:

1. **Portfolio reviewers.** Interviewers and engineers judge the project. They must see the security rigor in the UI, not only in the docs.
2. **End users.** A client app sends them to the login and consent pages. They want to sign in fast and trust that the page is real.
3. **Admins.** Platform admins and tenant admins register clients, approve redirect URIs and read audit events. The admin portal arrives in Phase 3.

The project owner is the first platform admin and the first client developer. Heimdall will be the login service for the owner's other projects.

## Product Purpose

Heimdall is a custom OAuth 2.1 and OpenID Connect identity provider. It is a portfolio project that aims at FAANG-level security rigor. Learning is the goal, and time is not a constraint. Success means two things. The owner can defend every design choice in an interview. Heimdall also runs as the real login service for the owner's other projects.

## Positioning

Every behavior traces back to a written threat model (STRIDE for each trust boundary, decisions D1 to D22) and to RFC text. The UI shows the same rigor. Each page states only true facts, and each security choice on a page has a reason someone can defend.

## Operating Context

- A client sends a user to `GET /oauth/v1/authorize`. Heimdall shows login when no valid session exists, and consent when consent is missing.
- Each tenant has its own subdomain, issuer, user pool, clients and signing keys (D19, D21). The login session is single sign-on across the clients of one tenant (D18).
- Phase 3 adds tenant onboarding, an admin portal with RBAC, an immutable audit log, WebAuthn/passkeys and revocable consent for each client and scope.
- Docs follow ASD-STE100 style by hand. See the writing rules in `CLAUDE.md`. UI copy uses the same terms as the glossary in `docs/threat-model.md`.

## Capabilities and Constraints

Security rules from `docs/threat-model.md` apply to every page. A design or stack choice must not weaken them:

- The pages use no inline script, and the server sends a strict `Content-Security-Policy`. Angular builds must use CSP nonces or hashes, not `'unsafe-inline'`.
- The pages cannot be framed: `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- The session cookie is `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, with one cookie for each tenant origin (D11, D21). The login and consent pages must be served from the tenant origin.
- Login, consent and logout forms carry an anti-forgery token. Consent and logout are POST only.
- The consent page reads the client and scope from the stored authorization request, never from form fields. It shows the encoded client name and the registered redirect URI host.
- Login shows one generic error for an unknown user and for a wrong password. Copy and timing must not reveal whether an account exists.
- Heimdall throttles failed logins. It does not lock accounts. Copy must not threaten a lockout.
- Passwords are 12 to 128 characters. Heimdall checks them against a breached-password list. It has no composition rules (D14, NIST SP 800-63B).
- No post-login return URL comes from the browser. Heimdall returns only to a stored `/authorize` request.

Open items:

- The threat model was written before the Angular decision. The login, session and consent section needs a review of the SPA-specific risks, such as the JSON login API and the bundle supply chain.
- Accessibility standard: not set yet.
- Tenant branding: not in scope now (see Brand Commitments).

## Brand Commitments

- The name is Heimdall. The repository is `heimdall-idp`, and the namespaces are `Heimdall.*`.
- The login and consent pages use only the Heimdall brand for now. Every tenant gets the same look. Tenant branding may come in Phase 3.
- No logo or visual identity exists yet.

## Evidence on Hand

- `docs/threat-model.md`: STRIDE tables for each endpoint, login, sessions and tenants, decisions D1 to D22, glossary and platform defaults.
- `docs/schema-design.md`, `docs/domain-model.md`, `docs/diagrams/`: schema, Domain rules and Mermaid diagrams.
- No users, customers, testimonials, benchmarks or conformance results exist yet. Do not invent them. The OpenID conformance suite run is a Phase 2 item, and k6 load targets come in Phase 4.
- Heimdall is not ready for production. No page may say or imply otherwise.

## Product Principles

1. Security is visible. A reviewer who opens any page can see the reason behind each choice.
2. Only true facts on the page. Copy states only what the system enforces.
3. The user signs in with as little friction as the security rules allow.
4. No page reveals data to an attacker, such as whether an account or tenant exists.
5. Admin tools cannot make a policy weaker than the platform limits (D15 to D17).
