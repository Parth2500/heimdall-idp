# Heimdall

The Public-Service Notice. Heimdall is a custom OAuth 2.1 and OpenID Connect identity provider. Its few pages (sign in, consent, error, signed out, account) read as notices from the issuer: who is asking, which origin the browser is on, what leaves, and nothing else. This system is condensed from the repository's `DESIGN.md` and adds the new logo.

## Logo

**The watcher's eye.** In the myths Heimdall guards the bridge to Asgard and can see a hundred leagues by day or night. The mark is an open eye whose pupil is a keyhole: it watches, and it grants access. It is drawn on the same square, flat geometry as the rest of the system.

| File | Use |
|---|---|
| `heimdall-mark.svg` | Default. Favicon and app icon. A white eye on a `lapis` square, the keyhole white in a lapis iris. |
| `heimdall-mark-dark.svg` | Dark theme. The same on `lapis`'s dark value (#2b3f99). |
| `heimdall-eye-on-lapis.svg` | The bare white eye with a see-through iris, for the issuer band beside the wordmark. |
| `heimdall-eye-ink.svg` | One ink (`ink`, #0b0c14), see-through iris. Print and single-colour contexts. |

- **Tile:** square, no radius (**The Square Corner Rule** covers the logo too).
- **In the band:** `heimdall-eye-on-lapis.svg` at 32px, 12px (`space-3`) before the wordmark "Heimdall" in the `wordmark` style. A client band (`client`) never carries the eye: it is not Heimdall.
- **In code:** `HdFrame` (ui-kit) draws the eye inline for `tone="issuer"` only, in `currentColor`, so it follows `on-lapis` like the wordmark. A tenant colour change needs no new SVG.
- **Colours:** lapis and white only, or ink alone. Never Signal Yellow: `focus` means keyboard focus and nothing else. Never red or green, which mean refuse and confirm.
- **Minimum size:** 16px. The keyhole drops out below that; use the mark at 16px or larger.
- **Never** round the tile, add a gradient, glow or shadow, or put the eye on a client's band or plate.

## Content fundamentals

Plain, factual and short, like a public notice. Say who asks and what leaves ("Huginn wants your email address"). Name the host exactly, in monospace. Errors say what happened and what to do next. Every page states that Heimdall is a development build.

## Colour

One committed blue, cool neutrals and three state colours. **The One Meaning Rule:** each colour means one thing on every page.

- `lapis` speaks and acts: the band, the origin plate, primary buttons, selection and the logo. Hover moves to `lapis-strong`. Text on it is `on-lapis`, the plate label `on-lapis-muted`.
- `client` replaces lapis in the frame of any site that is not Heimdall, such as the demo SPA.
- `focus` (yellow) with `focus-ink` marks keyboard focus only.
- `red` on `red-tint` refuses or fails; `green` on `green-tint` confirms.
- `ink`, `ink-muted`, `page`, `ground` and `rule` are the neutrals. `ink-muted` still passes 4.5:1 on `page` and `ground`.
- **The Tokens Not Components Rule.** Tenant branding changes token values, never a component.

## Typography

The system font stack only, by decision U8: no web font and no third-party origin on the sign-in page. Weight and size carry the hierarchy (**The Scale Contrast Rule**).

- `display` for the one page title, `headline` for sections, `wordmark` (800, the only 800) for the name in the band.
- `body` at 1.125rem with tabular numerals, `label` 700, `hint` 1rem, `small` 0.875rem.
- `mono` only for values a person or machine compares character by character: hosts, client IDs, scopes, error codes (**The Machine Value Rule**).

## Layout

**The One Frame Rule.** Every page is the 64px band (`space-band-height`), the origin plate hanging from it, one left-aligned column of `space-column` (30rem) inside a `space-frame` (64rem) track, and the footer on `ground`. Content starts `space-12` below the plate. Spacing follows a 4px rhythm. One column at every width.

## Shape and depth

- Every corner is square (`radius-none`). Controls are 48px (`space-control`) with a 2px ink border (`space-border`). An invalid input moves to a 4px red border.
- The only shaped edge is the origin plate's bottom notch: `clip-path: polygon(0 0, 100% 0, 100% 100%, 50% calc(100% - 0.5rem), 0 100%)`.
- Flat (**The Flat Notice Rule**). The only shadows are `shadow-focus-field` and `shadow-link-focus`.

## Do and don't

- Do put every page inside the one frame, and show the host in the plate in monospace.
- Do keep text at 4.5:1 in both themes.
- Don't add a web font, a card, a panel, a rounded corner or a side-stripe message.
- Don't use yellow for anything but focus, or give a state colour a second meaning.

## Not synced

Taken from `Parth2500/heimdall-idp` at `main@806e0b2` (`DESIGN.md`). Not included yet:

- **Components** (no bundle built): buttons (primary, secondary, quiet, busy, paired), status chip, problem, confirm and note boxes, inputs, band navigation, inline links, rule list, table, origin plate, band and busy line. Their rules are in `DESIGN.md`.
- `display` is fluid in the app (`clamp(2rem, 1.6rem + 1.6vw, 2.75rem)`); it is stored here at its largest step. `mono` inherits its size in use.
- The shadows use the light values of `focus` and `focus-ink` as literals; the app reads them from CSS variables.
- The logo uses Issuer Lapis, not the teal from the logo exploration, to keep **The One Meaning Rule**. Switching the brand colour is a token change.
- The account pages use the logo: the eye in the band and `favicon.svg` (with `favicon.ico` at 16, 32 and 48px made from it).
