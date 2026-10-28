# DR-004: Follow RFC 9700: no implicit flow, exact redirect URIs

- Date: 2026-10-18
- Status: Accepted. A correction to the first draft.
- Affects: D2, D17, and the `/authorize` section of the threat model.

## Before

The first draft did not exclude the implicit flow or redirect URI patterns.

## After

Heimdall supports only the authorization code flow with PKCE `S256` for user sign-in. A redirect URI must equal a registered URI exactly. No wildcard and no prefix match.

## Reason

RFC 9700 (OAuth 2.0 Security Best Current Practice) and OAuth 2.1 remove the implicit flow and require exact matching. Pattern matching has a long history of open redirects and code theft.

## Consequences

Clients register each URI. A test checks each near miss: a query added, a trailing slash, another case, another host.
