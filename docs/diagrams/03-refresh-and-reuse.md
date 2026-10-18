# 03 Refresh rotation and reuse detection

## Normal rotation

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant H as Heimdall
    participant DB as PostgreSQL

    C->>H: POST /token (refresh_token T1)
    H->>DB: BEGIN
    H->>DB: UPDATE refresh_tokens SET used_at = now() WHERE hash = T1 AND used_at IS NULL
    DB-->>H: 1 row (family F)
    H->>DB: Check family F is active (not revoked, idle and absolute limits)
    H->>DB: INSERT refresh token T2, set T1.replaced_by_id, move F.idle_expires_at
    H->>DB: COMMIT
    H->>C: new access token and T2
```

## Reuse of an old token (theft or retry)

```mermaid
sequenceDiagram
    autonumber
    participant C as Real client
    participant A as Attacker
    participant H as Heimdall
    participant DB as PostgreSQL

    C->>H: refresh_token T1
    H->>DB: Rotate T1 to T2 (1 row)
    H->>C: T2
    A->>H: refresh_token T1 (stolen earlier)
    H->>DB: UPDATE ... WHERE hash = T1 AND used_at IS NULL
    DB-->>H: 0 rows
    H->>DB: Read T1 (exists, used_at is set)
    H->>DB: UPDATE token_families SET revoked_at = now(), reason = reuse_detected
    H->>DB: INSERT audit event, raise alert
    H->>A: invalid_grant
    Note over C,DB: T2 is now invalid too. The real client must sign in again.
    C->>H: refresh_token T2
    H->>C: invalid_grant
```

There is no grace window. A client must save T2 before it uses it. See the refresh table in `docs/threat-model.md`.

## Two requests with the same code at the same time

```mermaid
sequenceDiagram
    autonumber
    participant R1 as Request 1
    participant R2 as Request 2
    participant DB as PostgreSQL

    par Both requests arrive together
        R1->>DB: UPDATE authorization_codes SET redeemed_at = now(), family_id = F1 WHERE hash = X AND redeemed_at IS NULL
    and
        R2->>DB: UPDATE authorization_codes SET redeemed_at = now(), family_id = F2 WHERE hash = X AND redeemed_at IS NULL
    end
    Note over DB: R1 takes the row lock. R2 waits.
    DB-->>R1: 1 row
    R1->>DB: COMMIT (family F1 and token created)
    DB-->>R2: 0 rows (row is now redeemed)
    R2->>DB: Read code X, family_id is F1
    R2->>DB: Revoke family F1, audit event, alert
    DB-->>R2: done
```

The check and the change are one statement. No application code runs between them.

## State of a family

```mermaid
stateDiagram-v2
    [*] --> Active: code redeemed
    Active --> Active: rotation (idle limit moves)
    Active --> Expired: idle or absolute limit passes
    Active --> Revoked: reuse, logout, admin, user disabled, consent removed
    Expired --> [*]: purged after 7 days
    Revoked --> [*]: purged after 7 days
```

## State of a code and a refresh token

```mermaid
stateDiagram-v2
    state "Authorization code" as Code {
        [*] --> Issued
        Issued --> Redeemed: first valid use
        Issued --> ExpiredCode: 5 minutes pass
        Redeemed --> Redeemed: second use triggers family revocation
    }
```

```mermaid
stateDiagram-v2
    state "Refresh token" as Token {
        [*] --> Valid
        Valid --> Used: rotation, replaced_by_id set
        Used --> Used: second use triggers family revocation
    }
```
