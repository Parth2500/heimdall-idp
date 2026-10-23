# ui-kit

Heimdall's own look for the account pages: Burning Bridge (decision U15 in `docs/frontend-design.md`). Only Heimdall's pages use it. A client, such as the demo SPA, must not use it.

| Part                         | What it is                                                                                                |
| ---------------------------- | --------------------------------------------------------------------------------------------------------- |
| `styles/heimdall.css`        | Tokens (night and day), fonts, base styles, controls, messages.                                           |
| `fonts/`                     | Archivo and JetBrains Mono, `woff2`, Latin subset. SIL Open Font License 1.1 (the `OFL-*.txt` files).     |
| `HdGate`                     | The page frame: brand, statement slot (`[hdStatement]`), gate plaque with the host, panel, motion switch. |
| `HdBridge`                   | The bridge scene. It shows the state `idle`, `busy`, `refused`, or `crossing`.                            |
| `HdMotionSwitch`, `HdMotion` | The switch that stops all movement. The default follows `prefers-reduced-motion`.                         |
| `HdIcon`                     | Authored icons on a 24px grid.                                                                            |

Tenant branding (Phase 3) changes token values, never a component.

Tests: `npm test` in `ui/` runs `ng test ui-kit` first.
