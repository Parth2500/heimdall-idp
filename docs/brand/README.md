# Heimdall

Burning Bridge (decision U15, 2026-10-23). Heimdall is a custom OAuth 2.1 and OpenID Connect identity provider. In the myths, Heimdall guards Bifröst, the burning bridge to Asgard. Each account page (sign in, consent, error, signed out) is the gate at the foot of that bridge: the host you stand at, one decision, and a bridge that shows the state of the request. `DESIGN.md` holds the full system. This page is the short version, with the logo.

## Logo

**The watcher's eye.** In the myths Heimdall guards the bridge to Asgard and can see a hundred leagues by day or night. The mark is an open eye whose pupil is a keyhole: it watches, and it grants access. It is drawn on the same square, flat geometry as the rest of the system.

| File | Use |
|---|---|
| `heimdall-mark.svg` | Default. Favicon and app icon. A white eye on a `lapis` square, the keyhole white in a lapis iris. |
| `heimdall-mark-dark.svg` | Dark theme. The same on `lapis`'s dark value (#2b3f99). |
| `heimdall-eye-on-lapis.svg` | The bare white eye with a see-through iris, for the issuer band beside the wordmark. |
| `heimdall-eye-ink.svg` | One ink (`ink`, #0b0c14), see-through iris. Print and single-colour contexts. |

- **Tile:** square, no radius (**The Square Corner Rule** covers the logo too).
- **On a page:** the eye at 32px, 12px before the wordmark "Heimdall", at the top left of the gate. A client never carries the eye: it is not Heimdall.
- **In code:** `HdGate` (ui-kit) draws the eye inline in `currentColor`, so it follows the display color in both themes. A tenant colour change needs no new SVG.
- **Colours:** lapis and white only, or one ink. Never ember: ember means the bridge's fire and keyboard focus. Never red, which means a refusal.
- **Minimum size:** 16px. The keyhole drops out below that; use the mark at 16px or larger.
- **Never** round the tile, add a gradient, glow or shadow, or put the eye on a client's band or plate.

## Content fundamentals

Plain, factual and short. The large statement may be figurative ("Gate shut."), but a plain heading always follows it and says the same thing ("Heimdall does not know this app"). Say who asks and what leaves. Name the host exactly, in monospace. Errors say what happened and what to do next. Every page states that Heimdall is a development build.

## Colour

**The One Meaning Rule:** each colour means one thing on every page.

- Frost blue (`bridge-1` to `bridge-4`, `act`) is the bridge and Heimdall's actions: primary buttons, selection, scope icons.
- Ember (`ember`, `ember-bright`) is the bridge's fire at rest and keyboard focus.
- Fire red (`fire`) is a refusal and nothing else: wrong credentials, the throttle, an error page, a Deny.
- Night (default dark) and day (light) themes follow `prefers-color-scheme`. Text passes 4.5:1 in both.
- **The Tokens Not Components Rule.** Tenant branding changes token values, never a component.

## Typography

Archivo (display and text) and JetBrains Mono (hosts, codes, scope names), self-hosted `woff2` files under the SIL Open Font License 1.1 (U8, U15). No font service and no third-party origin.

- The statement is Archivo 900, tight, two words to a line on desktop.
- Mono only for values a person or machine compares character by character (**The Machine Value Rule**).

## Layout

Desktop: statement on the left, gatehouse panel on the right, gate plaque at the bottom left, the bridge behind the panel. Phone: statement, plaque, then the form, with the bridge as a corner arc. The primary button stays in the first screen of a 390x667 phone.

## Motion

The bridge is state: lights drift (idle), run (busy), the outer band burns (refused), every band lights (crossing). The "Motion" switch stops it all; the default follows `prefers-reduced-motion`.

## Do and don't

- Do show the host on the gate plaque, with the address bar check line.
- Do keep a plain heading under every figurative statement.
- Don't use red for anything but a refusal, or ember for anything but the fire and focus.
- Don't load a font or anything else from a third-party origin.
- Don't use this look in a client app. The demo SPA keeps its own look.
