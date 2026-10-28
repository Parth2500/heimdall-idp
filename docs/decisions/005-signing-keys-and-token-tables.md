# DR-005: Signing keys for each tenant, and a table for token families

- Date: 2026-10-18
- Status: Accepted. A change to the first data model.
- Affects: The schema design.

## Before

The first data model had one `SecurityKey` table, a `ReplacedByTokenHash` column on refresh tokens, and no family table.

## After

`SigningKey` holds one key set for each tenant. `refresh_tokens.replaced_by_id` is a foreign key to the next token. `token_families` is its own table.

## Reason

Each tenant is its own issuer (D21), so it needs its own keys. A foreign key gives referential integrity, and the hash is not stored twice. A family row lets one statement revoke all tokens of a family.

## Consequences

A revocation is one `UPDATE` of one family row. The private keys stay in the key store (`IKeyMaterialStore`). The database holds only the public key and a reference.
