# Heimdall Schema Design (Phase 0)

This document defines the PostgreSQL schema. It uses the terms in the glossary of `docs/threat-model.md`. Decision IDs (D1 to D21) refer to that document.

The document has no C# code. The entities and the migrations are written by hand, from this design.

## Conventions

| Rule | Reason |
|---|---|
| Primary keys are UUIDv7 (`Guid.CreateVersion7()` in .NET). | Time-ordered keys keep index inserts local. They do not reveal counts. |
| Every tenant-owned table has `tenant_id` (not null, foreign key to `tenants`). | D20. |
| Every unique index and foreign key of a tenant-owned table includes `tenant_id`. | The database refuses a link between two tenants. Use composite foreign keys `(tenant_id, x_id)`. |
| Time columns are `timestamptz`. Expiry checks use the database clock (`now()`). | One clock. No drift between application servers. |
| Secrets, codes, and tokens are stored as `bytea` SHA-256 hashes. | D3. |
| Enums are `text` with a `CHECK` constraint. | Easier to change than a native enum type. |
| The Domain project has no EF Core types. All mapping is in `Infrastructure` with `IEntityTypeConfiguration`. | Dependencies point inward only. |

## Tables

### `tenants`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `host` | text, unique | The subdomain (D21). Lowercase. |
| `name` | text | |
| `status` | text | `active`, `suspended`. |
| `session_idle_seconds` | int | D18. Check: inside the hard bounds. |
| `session_absolute_seconds` | int | |
| `access_token_seconds` | int | Tenant default for clients. |
| `refresh_idle_seconds` | int | |
| `refresh_absolute_seconds` | int | |
| `created_at` | timestamptz | |

### `users`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | This value is the `sub` claim. It never changes and is never reused. |
| `tenant_id` | uuid | |
| `email` | text | As the user typed it. |
| `email_normalized` | text | Lowercase. **Unique with `tenant_id`.** |
| `password_hash` | text | Argon2id with parameters in the string. |
| `status` | text | `active`, `disabled`. |
| `created_at`, `password_changed_at` | timestamptz | `password_changed_at` ends older sessions. |

### `clients`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid | |
| `client_id` | text | The public identifier. **Unique with `tenant_id`.** |
| `name` | text | |
| `type` | text | `public`, `confidential`. |
| `token_endpoint_auth_method` | text | `none`, `client_secret_basic` in version 1. Check: `none` only for `public`. |
| `allowed_grant_types` | text[] | Check: `client_credentials` only for `confidential`. |
| `allowed_scopes` | text[] | |
| `require_consent` | bool | |
| `status` | text | `pending`, `active`, `disabled`. A client is `pending` until an admin approves it. |
| `access_token_seconds`, `refresh_idle_seconds`, `refresh_absolute_seconds` | int, null | Null means: use the tenant value (D15). Check constraints give the hard bounds. |
| `refresh_enabled` | bool | |
| `created_at`, `approved_by`, `approved_at` | | |

### `client_redirect_uris`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk` | uuid | Composite foreign key to `clients`. |
| `uri` | text | Stored exactly. **Unique with `client_pk`.** Matching is by exact string. |

### `client_secrets`
Two rows can be valid at the same time. This gives rotation without downtime.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk` | uuid | |
| `secret_hash` | bytea | |
| `created_at` | timestamptz | |
| `expires_at` | timestamptz, null | The old secret gets an expiry when the admin adds a new one. |
| `revoked_at` | timestamptz, null | |

A secret is valid when `revoked_at IS NULL` and (`expires_at IS NULL` or `expires_at > now()`). Heimdall compares the presented hash with all valid rows in fixed time (D4). The application limits a client to two valid secrets.

### `authorization_requests`
Heimdall stores the pending `/authorize` request here while the user signs in and gives consent. The consent form references this row and nothing else (see "User login, session, and consent pages").

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk` | uuid | |
| `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge` | text | The checked request. `code_challenge_method` is always `S256`, so there is no column. |
| `expires_at` | timestamptz | Short, for example 10 minutes. |

### `authorization_codes`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk`, `user_id` | uuid | |
| `code_hash` | bytea | **Unique with `tenant_id`.** |
| `redirect_uri` | text | For the exact-match check at `/token`. |
| `scope` | text | The approved scope. |
| `code_challenge` | text | |
| `nonce`, `auth_time` | | For the ID token. |
| `family_id` | uuid, null | Set at redemption. This is the link from a code to its family. |
| `created_at`, `expires_at` | timestamptz | `expires_at` is `created_at` plus 5 minutes. |
| `redeemed_at` | timestamptz, null | |

### `token_families`
The family is its own table. Reasons:
1. A family revocation is one update on one row.
2. The idle and absolute lifetimes belong to the family, not to one token.
3. The audit log and alerts can refer to one ID.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | This value is `TokenFamilyId`. |
| `tenant_id`, `client_pk`, `user_id` | uuid | |
| `source_code_id` | uuid | The code that started the family. |
| `scope` | text | The scope at the start. Refresh can only reduce it. |
| `created_at` | timestamptz | |
| `absolute_expires_at` | timestamptz | Fixed at creation. Rotation does not change it. |
| `idle_expires_at` | timestamptz | Moves forward at each rotation. It never passes `absolute_expires_at`. |
| `revoked_at` | timestamptz, null | |
| `revoked_reason` | text, null | `reuse_detected`, `user_logout`, `admin`, `user_disabled`, `consent_removed`. |

### `refresh_tokens`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `family_id` | uuid | Composite foreign key to `token_families`. |
| `token_hash` | bytea | **Unique with `tenant_id`.** |
| `created_at` | timestamptz | |
| `used_at` | timestamptz, null | Set when the client rotates the token. |
| `replaced_by_id` | uuid, null | Foreign key to the next token. This replaces the `ReplacedByTokenHash` column of the first draft. A foreign key gives referential integrity, and the hash is not stored twice. |

A token is valid when `used_at IS NULL` and its family is not revoked or expired. Only the newest token of a family can have `used_at IS NULL`.

### `sessions`
| Column | Type | Note |
|---|---|---|
| `id_hash` | bytea PK | The hash of the session ID in the cookie (D12). |
| `tenant_id`, `user_id` | uuid | |
| `created_at`, `last_seen_at` | timestamptz | |
| `auth_time` | timestamptz | For `max_age`. |
| `absolute_expires_at` | timestamptz | |
| `revoked_at` | timestamptz, null | |

The idle limit is `last_seen_at` plus the tenant's `session_idle_seconds`.

### `consents`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `user_id`, `client_pk` | uuid | **Unique together.** |
| `scope` | text | |
| `granted_at` | timestamptz | |
| `revoked_at` | timestamptz, null | A revoked consent is kept as evidence (repudiation). |

### `signing_keys`
D19: each tenant has its own keys.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid | |
| `kid` | text | **Unique with `tenant_id`.** |
| `algorithm` | text | Check: `RS256`. |
| `public_jwk` | jsonb | |
| `private_key_ref` | text | A Key Vault or KMS reference. For local development, an encrypted blob. Never a plain key. |
| `status` | text | `pending`, `active`, `retired`. |
| `published_at` | timestamptz | When the key enters the JWKS. |
| `signing_from` | timestamptz | At least one JWKS cache lifetime after `published_at`. |
| `retired_at`, `remove_after` | timestamptz, null | `remove_after` is the last signed token's expiry plus clock skew. |

Rules: a tenant has at most one `active` key. A key is in the JWKS when it is `pending` and published, `active`, or `retired` and before `remove_after`.

### `audit_events`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid, null | Null for platform events. |
| `occurred_at` | timestamptz | |
| `type` | text | For example `code.redeemed`, `code.reuse_detected`, `family.revoked`. |
| `actor_user_id`, `subject_user_id`, `client_pk`, `family_id` | uuid, null | |
| `source_ip` | inet | |
| `correlation_id` | text | |
| `data` | jsonb | Old and new values for configuration changes. Never secrets (D7). |

The application database role has `INSERT` and `SELECT` on this table. It has no `UPDATE` or `DELETE`. A separate role purges old rows.

## The atomic statements

These statements are the core of the security design. Each one is a single SQL command. A check in application code, followed by an update, is not allowed.

**Redeem a code** (`/token`, `authorization_code`). The application creates `@family_id` and inserts the family in the same transaction.
```sql
UPDATE authorization_codes
SET    redeemed_at = now(), family_id = @family_id
WHERE  tenant_id = @tenant AND code_hash = @hash
  AND  redeemed_at IS NULL AND expires_at > now()
RETURNING id, client_pk, user_id, redirect_uri, scope, code_challenge, nonce, auth_time;
```
One row means success. Zero rows means: unknown, expired, or reused. Then the application reads the row by hash. If `redeemed_at` is set, it is a reuse. Heimdall revokes `family_id` of that row, writes an audit event, and raises an alert. A second request waits on the row lock of the first. It sees the committed `family_id`, so the revocation reaches the right family.

**Rotate a refresh token** (`/token`, `refresh_token`).
```sql
UPDATE refresh_tokens
SET    used_at = now()
WHERE  tenant_id = @tenant AND token_hash = @hash AND used_at IS NULL
RETURNING id, family_id;
```
Zero rows and a row that exists with `used_at` set is a reuse. Heimdall then runs:
```sql
UPDATE token_families
SET    revoked_at = now(), revoked_reason = 'reuse_detected'
WHERE  id = @family_id AND revoked_at IS NULL;
```
After a successful rotation, the application checks that the family is not revoked or expired. It inserts the new token, sets `replaced_by_id`, and moves `idle_expires_at`. All of this runs in one transaction. If the family check fails, the transaction rolls back and Heimdall returns `invalid_grant`.

**Revoke a family** (`/revoke`, logout, admin) is the second statement above with another `revoked_reason`. The statement is idempotent.

## Indexes

| Table | Index | Reason |
|---|---|---|
| `authorization_codes` | unique `(tenant_id, code_hash)` | The redemption lookup and the single-use guarantee. |
| `authorization_codes` | `(expires_at)` | The purge job. |
| `refresh_tokens` | unique `(tenant_id, token_hash)` | The rotation lookup. |
| `refresh_tokens` | `(family_id)` | Revocation and the purge job. |
| `token_families` | `(user_id)`, `(client_pk)` | Revoke all families for a user or a client. |
| `sessions` | `(user_id)` | End all sessions of a user. |
| `users` | unique `(tenant_id, email_normalized)` | Sign-in lookup. |
| `clients` | unique `(tenant_id, client_id)` | Client lookup. |
| `audit_events` | `(tenant_id, occurred_at)`, `(family_id)` | Investigation. |

## What the database enforces and what the application enforces

| Rule | Database | Application |
|---|---|---|
| A code redeems only once | Unique hash and the conditional `UPDATE` | Handles the zero-row result. |
| Tenant isolation | Composite foreign keys, row-level security | EF Core global query filter |
| Public clients cannot use `client_credentials` | `CHECK` | Validation message for the admin |
| Setting values inside the hard bounds | `CHECK` | Platform limits from configuration (D16) |
| At most two valid secrets for a client | | Admin use case |
| One `active` signing key for each tenant | Partial unique index on `(tenant_id) WHERE status = 'active'` | Key rotation use case |
| Audit events cannot change | Role rights | |
| PKCE `S256`, `RS256` only (D17) | No column for the method. `CHECK (algorithm = 'RS256')` | |

The platform limits (minimum and maximum for each setting) live in configuration and are checked by the application. The database `CHECK` constraints hold only the outer bounds. They are the last defense if the application has a bug. They are wide on purpose, so a change in the limits does not need a migration.

## Row-level security (D20)

The application sets the tenant for each transaction with `SET LOCAL app.tenant_id = '...'`. A policy on each tenant-owned table compares `tenant_id` to `current_setting('app.tenant_id')`. Use `SET LOCAL`, not `SET`. With connection pooling, a plain `SET` stays on the connection and leaks to the next request. Platform operations use a separate role.

## Open questions

1. Is a UUIDv7 `sub` acceptable, or does a client need a pairwise `sub` for each client? (Pairwise subject identifiers stop clients from linking users. Defer to Phase 3.)
2. Where does `private_key_ref` point for local development? The first choice is an encrypted file with a key from the environment.
3. How long do we keep used refresh tokens and expired codes? The purge job needs a number. A short time is enough for codes. Keep used refresh tokens until their family expires, so reuse detection still works.
