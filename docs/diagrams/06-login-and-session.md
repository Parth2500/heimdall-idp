# 06 Login, session, and abuse controls

## Login request

Cheap checks run first. The expensive Argon2id hash runs last.

```mermaid
flowchart TD
    S(["POST login"]) --> RL{"IP rate limit passed?"}
    RL -- No --> T1["429 Too Many Requests"]
    RL -- Yes --> CS{"Anti-forgery token valid?"}
    CS -- No --> T2["400 Bad Request"]
    CS -- Yes --> TH{"Account throttle allows an attempt?"}
    TH -- No --> T3["Generic failure and delay"]
    TH -- Yes --> CC{"Concurrent hash limit passed?"}
    CC -- No --> T4["503 Retry later"]
    CC -- Yes --> LU["Load user by tenant and email"]
    LU --> HV["Argon2id verify (dummy hash if user is unknown)"]
    HV --> OK{"Password correct and user active?"}
    OK -- No --> F["Generic failure, count failure, audit event"]
    OK -- Yes --> NS["New session ID, set cookie, audit event"]
```

Failure responses and timing are the same for an unknown user and a wrong password (D5).

## Session cookie

```mermaid
flowchart LR
    CK["Cookie __Host-sid: random 256-bit ID, Secure, HttpOnly, SameSite=Lax, no Domain"]
    SV[("sessions table: hash of ID")]
    CK -->|"hash on each request"| SV
    SV --> CH{"Not revoked, idle limit and absolute limit not passed, created after password change?"}
    CH -- Yes --> OK["Valid session"]
    CH -- No --> NO["Show login page"]
```

## Abuse control layers

Throttle. Do not hard-lock accounts. A lock lets an attacker deny service to a victim.

```mermaid
flowchart TB
    L1["Layer 1: IP rate limit (cheap, first)"]
    L2["Layer 2: per-account backoff (delay grows with failures)"]
    L3["Layer 3: challenge after repeated failures (Phase 2)"]
    L4["Layer 4: temporary IP block on strong signals (Phase 2)"]
    L5["Layer 5: alert on credential stuffing patterns (Phase 2)"]
    L1 --> L2 --> L3 --> L4 --> L5
```

## Consent and CSRF

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant H as Heimdall
    participant DB as PostgreSQL

    B->>H: GET /authorize
    H->>DB: Store authorization request R (checked parameters)
    H->>B: Consent page for R (anti-forgery token, no client or scope fields)
    B->>H: POST consent (request ID R, anti-forgery token)
    H->>DB: Load R, read client and scope from R only
    H->>DB: Save consent, insert code
    H->>B: Redirect to redirect_uri
```
