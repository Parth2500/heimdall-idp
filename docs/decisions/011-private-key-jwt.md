# DR-011: Confidential clients can use private_key_jwt

- Date: 2026-10-28
- Status: Accepted. The owner chose inline keys, `aud` equal to the issuer only, and one method for each client.
- Affects: D10 (changed), D45 to D49 (new).

## Before

D10 said that confidential clients use `client_secret_basic` in version 1, and that `private_key_jwt` comes in Phase 2.

## After

A confidential client uses `client_secret_basic` or `private_key_jwt`, one method for each client. The operator registers the client's public keys inline (no `jwks_uri`). An assertion's `aud` must be exactly the issuer. Each assertion works once.

## Reason

For `client_credentials`, the shared secret was the only defense. With a key pair, Heimdall stores only a public key, so a database leak gives no credential. The `aud` rule follows draft-ietf-oauth-rfc7523bis and the 2025 fix for the audience injection attack. Inline keys need no outbound call and give no server-side request forgery.

## Consequences

Libraries that put the token endpoint URL in `aud` must be set to use the issuer. A key rotation needs the operator to update the key set. A `jwks_uri` can come in a later phase. The secrets of a client that moves to keys stop working.
