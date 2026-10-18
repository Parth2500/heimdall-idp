# 01 Architecture

## Layers

Dependencies point inward only. The Domain project has no outward dependency and no EF Core types.

```mermaid
flowchart TB
    subgraph Api["Heimdall.Api (composition root)"]
        EP["Endpoints: authorize, token, userinfo, revoke, discovery, jwks, session and consent API"]
        MW["Middleware: tenant by host, rate limit (Phase 2), correlation ID"]
        JOBS["Jobs: signing keys, purge"]
    end
    subgraph Infra["Heimdall.Infrastructure"]
        EF["EF Core and Npgsql"]
        SQL["Hot-path SQL: redeem code, rotate refresh token"]
        RLS["Tenant interceptor: sets app.tenant_id for row-level security"]
        KEYS["Key storage: dev JSON file, Key Vault or KMS"]
        HASH["Argon2id password hasher"]
    end
    subgraph App["Heimdall.Application"]
        UC["Use cases"]
        PORTS["Interfaces: stores, clock, hasher, key source"]
    end
    subgraph Dom["Heimdall.Domain"]
        ENT["Entities: Tenant, User, Client, AuthorizationCode, TokenFamily, RefreshToken, Session, Consent, SigningKey, AuditEvent"]
        RULES["Rules: Pkce, TokenHash, ScopeRules, RedirectUriRules, SigningKeyRotation"]
    end

    Api --> App
    Api --> Infra
    Infra --> App
    App --> Dom
    Infra -.implements.-> PORTS
```

## System context and trust boundaries

B1 to B5 match the trust boundary table in `docs/threat-model.md`.

```mermaid
flowchart LR
    U["User agent (browser)"]
    C["Client application"]
    R["Resource server (API)"]
    subgraph H["Heimdall"]
        direction TB
        A["App servers (stateless)"]
    end
    DB[("PostgreSQL")]
    K["Key store"]
    CDN["CDN or cache"]

    U <-->|"B1: login and consent pages"| A
    C <-->|"B2: authorize redirect, token, revoke"| A
    U <--> C
    A <-->|"B3: SQL as heimdall_app (row-level security), jobs as heimdall_platform"| DB
    A <-->|"B4: sign"| K
    R -->|"B5: fetch JWKS"| CDN
    CDN --> A
    C -->|"access token"| R
```

## Settings layers (D15 to D17)

```mermaid
flowchart TB
    P["Platform defaults and limits (configuration)"]
    T["Tenant settings (tenants table)"]
    CL["Client settings (clients table, null means inherit)"]
    FIX["Fixed rules with no setting: PKCE S256, RS256, exact redirect URIs, family revocation on reuse, hashing at rest"]

    P -->|"limits: minimum and maximum"| T
    T -->|"default for"| CL
    FIX -.applies to all.-> P
```
