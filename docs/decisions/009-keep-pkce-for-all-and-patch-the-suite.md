# DR-009: Keep PKCE for all clients and patch the conformance suite

- Date: 2026-10-28
- Status: Accepted. Decided by the owner.
- Affects: D2 (not changed).

## Before

The OpenID conformance suite sends no PKCE in its OpenID Connect modules. Heimdall refuses a request without PKCE `S256` (D2). One option was a PKCE exception for confidential clients.

## After

D2 stays. A local patch makes the suite send PKCE `S256`. The results are in `docs/conformance.md`.

## Reason

OAuth 2.1 requires PKCE for every client. An exception for a test would weaken every confidential client in production.

## Consequences

The results are not an official OpenID certification. A certification needs the unchanged suite. The patch is in `tools/conformance/`.
