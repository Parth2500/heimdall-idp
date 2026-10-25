# Mockups: Ledger card design

Static HTML mockups of a proposed new look for the account pages. They are design references, not production code. No build step uses them.

**Status:** approved on 2026-10-25 as U16 in `docs/frontend-design.md`. U16 replaces U15 (Burning Bridge). The mockups are a reference. The UI may change. The features stay.

## Open the mockups

Open `index.html` in a browser. It lists each screen with a light and a dark version. Links inside a page go to the next page in the flow.

## Layout

| Path | Content |
|---|---|
| `index.html` | List of all screens, grouped by flow. |
| `pages/*.html` | One page for each screen. A `-Dark` suffix marks the dark version. |

## Flows

| Group | Screens |
|---|---|
| Sign in | Email step, password step, account picker, consent, sign-in with all options. |
| States | Busy, wrong password, error page (request refused), signed out. |
| Two-step sign-in | Method list, authenticator code, passkey, recovery code. |
| Sign-up | Create account, email code, set password, account ready. |
| Invitation and other providers | Accept invitation, invitation expired, link account, complete profile. |
| Recovery | Forgot password, new password. The email code step uses the sign-up code page. |
| Security setup | Two-step required by the tenant, authenticator setup, recovery codes, passkey name, stay signed in. |
| Edge states | Request expired, re-authentication, new permissions, password changed, JavaScript off. |
| Device sign-in | Enter code, approve device, device connected (RFC 8628). |
| Emails | Verification code, invitation, reset code, new sign-in alert, security change. |
| Account portal | Overview, security, devices, apps with access, recent activity. |

## Design rules

- The page is a centered card, 448 px wide at most. On a phone, the card loses its border and fills the screen.
- Every page shows the tenant host, so that a user can compare it with the address bar.
- Red means a refusal only. Blue is for Heimdall's actions. Yellow is keyboard focus only.
- Fonts: IBM Plex Sans and IBM Plex Mono, both under the SIL Open Font License 1.1.
- The emails use system fonts, because most mail clients do not load web fonts.

## Differences from production rules

- The mockups load IBM Plex from Google Fonts. Production pages must serve fonts from their own origin (N5, U8).
- The data in the mockups is example data: accounts, dates, places, sessions and codes.
- The mockups use flexbox and grid. Production emails need table layout, inline styles and a plain-text version.
- Many screens show features that do not exist yet: sign-up, invitations, other providers, two-step sign-in, passkeys, device sign-in, the account picker (#41), stored consent and the account portal (Phase 3).

## Sources

- Design canvas, with every board and the earlier directions: https://claude.ai/artifact/Xs9NJcucEnZ2pG8sCutCS7
- Flow map in FigJam: https://www.figma.com/board/t2QJL4pqZy1h9oRkI1Y4d0

The pages were exported from the canvas. To change a screen, change it on the canvas and export it again. Do not edit the exported HTML by hand.
