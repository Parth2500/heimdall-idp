# DR-001: Angular for all user interfaces

- Date: 2026-10-18
- Status: Accepted. Decided by the owner.
- Affects: The UI stack in CLAUDE.md.

## Before

The plan used React and Next.js for the user interfaces.

## After

Angular builds every user interface: the login, consent, and sign-out pages, the admin portal, and the demo SPA.

## Reason

The owner did not record a reason with the choice. One framework for every page gives one build, one dependency review, and one set of security rules (U1 to U8).

## Consequences

The account pages are Angular (`ui/projects/account`). The demo SPA uses `angular-auth-oidc-client`. The browser library (#42) wraps `oidc-client-ts`, which has no framework dependency.
