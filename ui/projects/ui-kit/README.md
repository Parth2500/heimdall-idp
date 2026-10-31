# ui-kit

Heimdall's own look for the account pages: Ledger card (decision U16 in `docs/frontend-design.md`). Only Heimdall's pages use it. A client, such as the demo SPA, must not use it.

| Part                  | What it is                                                                                                 |
| --------------------- | ---------------------------------------------------------------------------------------------------------- |
| `styles/heimdall.css` | Tokens (night and day), fonts, base styles, controls, messages, the focus ring.                            |
| `fonts/`              | IBM Plex Sans and IBM Plex Mono, `woff2`, Latin subset. SIL Open Font License 1.1 (the `OFL-*.txt` files). |
| `HdCard`              | The page frame: brand, host block, title slot (`[hdStatement]`), task slot, footer. Takes a `CardState`.   |
| `HdIcon`              | Authored icons on a 24px grid.                                                                             |

Keyboard focus is one 3px ring in the action blue, with a 2px gap. It has about 7:1 contrast in both themes. WCAG 2.2 asks for 3:1 (1.4.11).

Tenant branding (Phase 3) changes token values, never a component.

Tests: `pnpm test` in `ui/` runs `ng test ui-kit` first.
