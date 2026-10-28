# DR-010: /userinfo reads the token family (D44)

- Date: 2026-10-28
- Status: Accepted. Decided by the owner.
- Affects: D33 (narrowed), D44 (new).

## Before

D33 said that access tokens stay valid until `exp` after a sign-out. `/userinfo` checked only the signature, `exp`, and the user.

## After

`/userinfo` reads the token's family and its user in one query. A revoked or missing family makes the token invalid at once. A resource server that checks tokens offline still accepts them until `exp`.

## Reason

The conformance test `oidcc-codereuse-30seconds` found that `/userinfo` still accepted a token after a code reuse revoked its family. Introspection already read the family (D38).

## Consequences

The read replaces the user read, so `/userinfo` still opens one connection. A sign-out, a reuse, and `/revoke` now stop the token at `/userinfo` at once.
