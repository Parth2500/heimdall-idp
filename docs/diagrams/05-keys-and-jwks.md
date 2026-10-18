# 05 Signing keys and JWKS

## Key lifecycle

A new key is published in the JWKS before it signs anything. An old key stays in the JWKS until its last token has expired.

```mermaid
stateDiagram-v2
    [*] --> Pending: key created
    Pending --> Active: signing_from reached (at least one JWKS cache lifetime after publish)
    Active --> Retired: newer key becomes active
    Retired --> Removed: remove_after reached (last token expiry plus clock skew)
    Active --> Removed: emergency removal after compromise
    Removed --> [*]

    note right of Pending
        In the JWKS. Does not sign.
    end note
    note right of Active
        In the JWKS. Signs new tokens.
        One active key for each tenant.
    end note
    note right of Retired
        In the JWKS. Does not sign.
        Old tokens still verify.
    end note
```

## Rotation over time

```mermaid
flowchart LR
    subgraph t0["Before rotation"]
        A0["Key A: active"]
    end
    subgraph t1["Step 1: publish"]
        A1["Key A: active"]
        B1["Key B: pending (in JWKS)"]
    end
    subgraph t2["Step 2: switch (after cache lifetime)"]
        A2["Key A: retired (in JWKS)"]
        B2["Key B: active"]
    end
    subgraph t3["Step 3: remove (after last A token expires)"]
        B3["Key B: active"]
    end
    t0 --> t1 --> t2 --> t3
```

## JWKS request path

```mermaid
flowchart LR
    RS["Resource server"] --> CDN["CDN or reverse proxy"]
    CDN -->|"cache miss"| APP["Heimdall app server"]
    APP --> MEM["In-memory key set"]
    MEM -.refresh on rotation.-> DB[("signing_keys")]
```

The app server never reads the database for each JWKS request. The response has `Cache-Control: public, max-age=...` and an `ETag`.
