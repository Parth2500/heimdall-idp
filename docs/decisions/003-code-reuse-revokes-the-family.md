# DR-003: Code reuse revokes the token family

- Date: 2026-10-18
- Status: Accepted. A correction to the first draft.
- Affects: D17 and the `/token` section of the threat model (code reuse).

## Before

The first draft said that a reused code "invalidates active sessions for that user/client pair".

## After

A reused code revokes the token family that the first redemption of that code started, and Heimdall raises a security alert. No grace window applies.

## Reason

The draft rule was vague and had the wrong shape. A user can have many sessions and many families with one client. Only the family from that code is in danger. The family is the unit that a revocation can name exactly.

## Consequences

`authorization_codes` records `family_id` in the redemption statement. A reuse finds the family and revokes it. Since D44, `/userinfo` also refuses the access tokens of that family at once.
