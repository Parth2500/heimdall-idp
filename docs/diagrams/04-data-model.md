# 04 Data model

Only key columns are shown. The full design is in `docs/schema-design.md`.
Every tenant-owned table has `tenant_id`. Every unique index and foreign key includes it (D20).

```mermaid
erDiagram
    tenants ||--o{ users : has
    tenants ||--o{ clients : has
    tenants ||--o{ signing_keys : has
    tenants ||--o{ sessions : has
    clients ||--o{ client_redirect_uris : lists
    clients ||--o{ client_secrets : "has (max 2 valid)"
    clients ||--o{ authorization_requests : receives
    clients ||--o{ authorization_codes : receives
    clients ||--o{ token_families : owns
    clients ||--o{ consents : receives
    users ||--o{ sessions : opens
    users ||--o{ consents : grants
    users ||--o{ authorization_codes : "is subject of"
    users ||--o{ token_families : "is subject of"
    token_families ||--o{ refresh_tokens : contains
    authorization_codes }o--o| token_families : "starts"
    refresh_tokens |o--o| refresh_tokens : "replaced_by"

    tenants {
        uuid id PK
        text host UK
        text status
        int session_idle_seconds
        int refresh_absolute_seconds
    }
    users {
        uuid id PK
        uuid tenant_id FK
        text email_normalized UK
        text password_hash
        text status
        timestamptz password_changed_at
    }
    clients {
        uuid id PK
        uuid tenant_id FK
        text client_id UK
        text type
        text status
        text_array allowed_grant_types
        text_array allowed_audiences
    }
    client_redirect_uris {
        uuid id PK
        uuid client_pk FK
        text uri UK
    }
    client_secrets {
        uuid id PK
        uuid client_pk FK
        bytea secret_hash
        timestamptz expires_at
        timestamptz revoked_at
    }
    authorization_requests {
        uuid id PK
        uuid client_pk FK
        text code_challenge
        timestamptz expires_at
    }
    authorization_codes {
        uuid id PK
        uuid tenant_id FK
        bytea code_hash UK
        uuid family_id FK
        timestamptz expires_at
        timestamptz redeemed_at
    }
    token_families {
        uuid id PK
        uuid tenant_id FK
        uuid source_code_id
        timestamptz absolute_expires_at
        timestamptz idle_expires_at
        timestamptz revoked_at
    }
    refresh_tokens {
        uuid id PK
        uuid family_id FK
        bytea token_hash UK
        timestamptz used_at
        uuid replaced_by_id FK
    }
    sessions {
        bytea id_hash PK
        uuid user_id FK
        timestamptz absolute_expires_at
        timestamptz revoked_at
    }
    consents {
        uuid id PK
        uuid user_id FK
        uuid client_pk FK
        text scope
        timestamptz revoked_at
    }
    signing_keys {
        uuid id PK
        uuid tenant_id FK
        text kid UK
        text status
        timestamptz remove_after
    }
    audit_events {
        uuid id PK
        uuid tenant_id
        timestamptz occurred_at
        text type
        uuid family_id
    }
```

`audit_events` has no foreign keys on purpose. The rows must outlive the rows they describe. The application role can only insert and select.
