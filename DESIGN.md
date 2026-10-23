---
name: Heimdall
description: The account pages of the Heimdall identity provider. Each page is the gate at the foot of the burning bridge.
colors:
  ground: "#07080d"
  star: "#e8ecff"
  panel: "#10121c"
  raised: "#181b2a"
  field: "#07080d"
  line: "#262a3d"
  line-field: "#6a7396"
  ink: "#f2f4fa"
  ink-muted: "#9aa3b8"
  act: "#4c6fff"
  act-strong: "#7390ff"
  on-act: "#07080d"
  link: "#a9bbff"
  bridge-1: "#4c6fff"
  bridge-2: "#2b3f99"
  bridge-3: "#1e2f7a"
  bridge-4: "#14205a"
  bridge-light: "#dfe6ff"
  ember: "#ff7a45"
  ember-bright: "#ff7a45"
  ember-banked: "#5a2414"
  fire: "#e5372b"
  fire-text: "#ff8a80"
  fire-tint: "#24100f"
  ground-day: "#e7ebf5"
  panel-day: "#ffffff"
  raised-day: "#eef1f8"
  field-day: "#ffffff"
  line-day: "#c9d0e2"
  line-field-day: "#5d6686"
  ink-day: "#0b0d18"
  ink-muted-day: "#4a5168"
  act-day: "#3352e0"
  act-strong-day: "#2640b8"
  on-act-day: "#ffffff"
  link-day: "#2640b8"
  bridge-1-day: "#3352e0"
  bridge-2-day: "#23338a"
  bridge-3-day: "#182566"
  bridge-4-day: "#0f1846"
  bridge-light-day: "#ffffff"
  ember-day: "#c2410c"
  ember-banked-day: "#f2b49a"
  fire-text-day: "#b3261e"
  fire-tint-day: "#fdecea"
typography:
  display:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "clamp(6rem, 1rem + 11vw, 11.5rem)"
    fontWeight: 900
    lineHeight: 0.86
    letterSpacing: "-0.045em"
    fontVariation: "'wdth' 86"
  display-phone:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "clamp(3.5rem, 1.5rem + 9vw, 10rem)"
    fontWeight: 900
    lineHeight: 0.86
    letterSpacing: "-0.045em"
    fontVariation: "'wdth' 86"
  headline:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "clamp(1.375rem, 1rem + 1.2vw, 2rem)"
    fontWeight: 800
    lineHeight: 1.15
    letterSpacing: "-0.02em"
  lead:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 400
    lineHeight: 1.4
  title:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 700
    lineHeight: 1.3
  body:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "'tnum'"
  small:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.45
  note:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 700
    lineHeight: 1.5
  wordmark:
    fontFamily: "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "-0.02em"
  mono-host:
    fontFamily: "'JetBrains Mono', ui-monospace, 'SF Mono', 'Cascadia Mono', 'DejaVu Sans Mono', Menlo, Consolas, monospace"
    fontSize: "clamp(1.25rem, 0.9rem + 1.2vw, 2rem)"
    fontWeight: 700
    lineHeight: 1.2
  mono-value:
    fontFamily: "'JetBrains Mono', ui-monospace, 'SF Mono', 'Cascadia Mono', 'DejaVu Sans Mono', Menlo, Consolas, monospace"
    fontSize: "1.375rem"
    fontWeight: 700
    lineHeight: 1.3
  mono-input:
    fontFamily: "'JetBrains Mono', ui-monospace, 'SF Mono', 'Cascadia Mono', 'DejaVu Sans Mono', Menlo, Consolas, monospace"
    fontSize: "1rem"
    fontWeight: 400
rounded:
  none: "0px"
spacing:
  "1": "0.25rem"
  "2": "0.5rem"
  "3": "0.75rem"
  "4": "1rem"
  "5": "1.25rem"
  "6": "1.5rem"
  "8": "2rem"
  "10": "2.5rem"
  "12": "3rem"
  control: "3.5rem"
  panel-width: "27.5rem"
components:
  button-primary:
    backgroundColor: "{colors.act}"
    textColor: "{colors.on-act}"
    rounded: "{rounded.none}"
    padding: "0.5rem 1.5rem"
    height: "3.75rem"
  button-primary-hover:
    backgroundColor: "{colors.act-strong}"
    textColor: "{colors.on-act}"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "0.5rem 1.5rem"
    height: "3.75rem"
  button-secondary-hover:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.ink}"
  button-quiet:
    backgroundColor: "transparent"
    rounded: "{rounded.none}"
    padding: "0.25rem 0.75rem"
  input:
    backgroundColor: "{colors.field}"
    textColor: "{colors.ink}"
    typography: "{typography.mono-input}"
    rounded: "{rounded.none}"
    padding: "0.5rem 1rem"
    height: "3.5rem"
  gatehouse-panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "2rem 2rem 1.5rem"
    width: "27.5rem"
  problem:
    backgroundColor: "{colors.fire-tint}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "1rem 1.25rem"
  fact:
    backgroundColor: "{colors.field}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "1rem 1.25rem"
  motion-switch:
    backgroundColor: "transparent"
    textColor: "{colors.ink-muted}"
    rounded: "{rounded.none}"
    padding: "0 0.75rem"
    height: "2.75rem"
---

# Design System: Heimdall

## Overview

**Creative North Star: "The Burning Bridge"**

In the myths, Heimdall guards Bifröst, the burning bridge to Asgard. Each account page is the gate at the foot of that bridge. The page shows three things: the host where the user stands, one decision, and a bridge that shows the state of the request. The owner approved this world on 2026-10-23 (decision U15 in `docs/frontend-design.md`). It replaces "The Public-Service Notice" (U13).

The scene is dark and still by default, with a few cold stars. Frost bands make a quarter arc behind the task. An ember thread burns along the arc at rest. The page is flat and square. Size and weight rank the content, not boxes or shadows. One very large statement in Archivo 900 stands at the left, like a sign at the gate. The task sits in one flat gatehouse panel.

The bridge is decoration with a job. It shows the state of the crossing, but no state depends on it. The text, the focus, and `aria-live` carry every state. The world rejects the centered SaaS card on a gradient.

The tokens and the frame are in `ui/projects/ui-kit` (`styles/heimdall.css`, `HdGate`, `HdBridge`, `HdMotionSwitch`, `HdIcon`). Tenant branding (Phase 3) changes token values, never a component.

**Scope.** This system covers Heimdall's own pages only: login, consent, error, and signed out (`ui/projects/account`). The demo SPA is a client, not Heimdall. It keeps the old U13 look in `ui/projects/demo/src/client-kit.css`, so a user can see that it is a different site. Huginn and every other client are also out of this system.

**Key Characteristics:**
- Three color meanings: frost, ember, and fire. Each color means one thing on every page.
- Night (the default scene) and day themes from `prefers-color-scheme`.
- The bridge is state: idle, busy, refused, crossing.
- A visible "Motion" switch stops all movement.
- Archivo 900 statement at 86% width, tight tracking. JetBrains Mono only for machine values.
- Square controls, 56px tall. No radius anywhere.
- The gate plaque names the host and asks the user to compare it with the address bar.

## Colors

A near-black sky, cold frost blues, and one warm fire that changes meaning only on a refusal. The frontmatter keys without a suffix are the night values. The `-day` keys are the day values of the same token.

### Primary
- **Bifröst Frost** (`act`, `bridge-1`): The bridge and Heimdall's actions. The primary button, the selection, the "on" track of the motion switch, the caret, and the scope icons use it. Day uses a deeper lapis (`act-day`).
- **Frost Bands** (`bridge-2`, `bridge-3`, `bridge-4`): The inner bands of the arc, from light to deep. Only the bridge uses them.
- **Bridge Light** (`bridge-light`): The lights that move along the bands. At night they add to the band color (`mix-blend-mode: plus-lighter`).
- **Frost Link** (`link`): Text links. Links have a 1px underline, and 2px on hover.

### Secondary
- **Ember** (`ember`): Keyboard focus (the CSS sets it as `--hd-focus`) and the fire mark (the full stop) of the statement. Day uses a darker burnt orange (`ember-day`), so the ring and the mark pass 3:1 on the day ground.
- **Ember Thread** (`ember-bright`): The thin fire line along the arc at rest.
- **Banked Ember** (`ember-banked`): The guard band at the outer edge of the arc at rest.

### Tertiary
- **Guard Fire** (`fire`): A refusal and nothing else. The outer band flares to it, the panel border and the fire mark turn to it, and the problem box and an invalid field use it as a border.
- **Fire Text** (`fire-text`) and **Fire Tint** (`fire-tint`): The problem title, a field error, an error code, and the background of the problem box.

### Neutral
- **Night Sky** (`ground`): The page background. Day: **Dawn Sky** (`ground-day`).
- **Stars** (`star`): The stars of the night sky. Day has no stars (`--hd-star: transparent`).
- **Gatehouse** (`panel`): The panel that holds the task. Day: white.
- **Raised** (`raised`): The hover fill of the secondary and quiet buttons.
- **Field** (`field`): The input fill and the fact box fill.
- **Line** (`line`): The panel border, the rule between list rows, and the note rule.
- **Field Line** (`line-field`): The input border and the scrollbar thumb.
- **Ink** (`ink`) and **Muted Ink** (`ink-muted`): Text. Muted ink is for help text, the plaque label, and the check line. The display color equals ink.

### Named Rules
**The One Meaning Rule.** Frost is the bridge and Heimdall's actions. Ember is the bridge's fire at rest and keyboard focus. Fire red is a refusal. Use no color for a second meaning.

**The Fire Means No Rule.** Red appears only when Heimdall refuses or the user selects Deny: wrong credentials, the throttle, an error page with a refusal. A "Heimdall is busy" error is not a refusal, so it stays idle and has no red.

**The Tokens Not Components Rule.** A theme or a tenant changes token values only. Components read `var(--hd-*)`.

## Typography

**Display Font:** Archivo (variable, `wdth` 62 to 125, `wght` 100 to 900), with `system-ui` as fallback
**Body Font:** Archivo
**Label/Mono Font:** JetBrains Mono (variable, `wght` 100 to 800), with `ui-monospace` as fallback

**Character:** A heavy, condensed, tightly tracked display that reads like letters cut in a gate. A plain grotesque for the text, and a clear monospace for the values a person compares character by character.

Both fonts are self-hosted `woff2` files in `ui/projects/ui-kit/fonts/`, under the SIL Open Font License 1.1. Heimdall serves them from its own origin (U8). No font service is used.

### Hierarchy
- **Display** (900, width 86%, `clamp(6rem, 1rem + 11vw, 11.5rem)` on desktop, `clamp(3.5rem, 1.5rem + 9vw, 10rem)` below 64rem, line height 0.86, tracking -0.045em): The statement at the gate, for example "Sign in." On desktop the measure is 3em, so the statement stacks about two words to a line. The text is balanced.
- **Headline** (800, `clamp(1.375rem, 1rem + 1.2vw, 2rem)`, line height 1.15, tracking -0.02em, measure 22em): The plain heading under a figurative statement. When the statement is figurative, the statement is `aria-hidden` and this line is the `h1`.
- **Lead** (400, 1.375rem, line height 1.4): The main sentence of a panel that has no form.
- **Title** (700, 1.0625rem, line height 1.3): Section headings in the panel, for example "Huginn asks to".
- **Body** (400, 1.0625rem, line height 1.5, tabular numbers): All running text.
- **Small** (400, 0.9375rem, line height 1.45): Help text under a task, in muted ink.
- **Note** (400, 0.8125rem): The development build note at the foot of the panel, and fact labels.
- **Label** (700, body size): Field labels. Every field has a visible label.
- **Mono host** (JetBrains Mono 700, `clamp(1.25rem, 0.9rem + 1.2vw, 2rem)`, line height 1.2): The host on the gate plaque.
- **Mono value** (JetBrains Mono 700, 1.375rem): A fact value, for example the redirect host.
- **Mono input** (JetBrains Mono 400, 1rem): Text in an input, so a user can read each character.

### Named Rules
**The Machine Value Rule.** Use JetBrains Mono only for hosts, codes, client IDs, scope names, and input text. Never use it for prose or headings.

**The Plain Heading Rule.** A figurative statement ("Gate shut.") always has a plain heading under it that says the same thing ("Heimdall does not know this app").

**The Fire Mark Rule.** A statement ends with one punctuation mark in the fire span (`.` or `?`). The mark is ember at rest and fire red on a refusal. Use no other colored glyph in the statement.

## Layout

The system uses a 4px rhythm (`spacing` 1 to 12). Panel content stacks with 1.5rem gaps; tight stacks use 0.75rem.

**Desktop (64rem and wider).** The wordmark is at the top left. The motion switch is at the top right. Below them, a two-column grid: the statement on the left, centered vertically; the gatehouse panel on the right (27.5rem wide), centered vertically; the gate plaque at the bottom left. The columns have a 2.5rem gap. The page padding is 2rem, 3rem, and 2.5rem. The bridge rises from the bottom middle, behind the panel, to the right edge. Its size comes from `min(100vw, 142vh)`, so it keeps its place at each window shape.

**Tablet (40rem to 64rem).** The phone order, in one column of at most 34rem. The bridge arc is larger.

**Phone (below 40rem).** One column in this order: wordmark, motion switch (under the wordmark, in the clear sky left of the arc), statement, plaque, panel. The panel has no border or fill; its content sits on the sky. The bridge is a corner arc at the top right, seen from below (`scaleY(-1)`). The primary button stays in the first screen of a 390x667 viewport. On the consent page, the statement and the scope rows get tighter so Allow and Deny also stay in the first screen.

**The First Screen Rule.** The motion switch and the primary action are in the first screen on every layout.

## Elevation & Depth

The system is flat. No surface has a shadow. A 1px line and a change of fill separate the panel, the fields, and the facts from the sky. Depth comes only from the scene: the bridge sits behind the content (`z-index: -1`), and the stars stay in the first screen of sky. The bridge uses SVG blur for its soft lights and for the fire glow on a refusal. These are light, not elevation.

### Shadow Vocabulary
- **Invalid field** (`box-shadow: inset 0 0 0 1px var(--hd-fire)`): Doubles the fire border of an invalid input to 2px. It is a border, not a lift.

### Named Rules
**The Flat Gate Rule.** No drop shadow on any component. Separate surfaces with a 1px line or a fill change.

## Shapes

Every corner is square (`rounded.none`). Buttons, inputs, the panel, the problem box, the fact box, the switch track, and its knob have no radius. Borders are 1px; forced colors make them 2px. The icons are authored on a 24px grid with a 1.75 stroke, square caps, and miter joins, so they match the controls. The only curve in the system is the arc of the bridge: concentric quarter circles, with sky in the gaps between bands. The watcher's eye (the logo) is the other curved form. It is drawn in `currentColor` at 32px, 12px before the wordmark.

**The Square Corner Rule.** No radius on any control, box, or tile, including the logo tile.

## Components

### Buttons
Heavy, square, and wide. The primary action reads its words first and its direction last.
- **Shape:** Square (0px). Height is the control height plus 4px (60px). Weight 800.
- **Primary ("go"):** Frost fill, on-act text, 1px frost border. Full width in the panel. The words are at the start and an arrow icon is at the end (`justify-content: space-between`).
- **Hover:** The fill goes to `act-strong` in 160ms. The arrow moves 4px to the right in 240ms.
- **Focus:** A 3px ember outline with a 2px gap. The ring is readable on the panel, the field, and the frost button.
- **Busy:** The button keeps full contrast and its fill. Its words change ("Signing in") and its arrow goes to 50% opacity. It uses `aria-disabled`, not `disabled`, so it keeps focus.
- **Secondary:** Transparent, ink text, `ink-muted` border. Hover fills it with `raised`. "Show" next to the password and "Deny" on consent use it.
- **Quiet:** Transparent, `line-field` border, weight 600, small padding. For a minor action.
- **Pair:** Allow and Deny sit in a grid of 1.2fr and 1fr, with a 0.75rem gap. Allow is the primary.

### Inputs / Fields
- **Style:** Square, 56px tall, 1px `line-field` border, `field` fill, JetBrains Mono at 1rem. The label is above, in bold.
- **Hover:** The border goes to `ink-muted`.
- **Focus:** The ember ring sits on the edge (offset 0), and the border turns ember.
- **Error:** The border turns fire red and doubles to 2px. A field error in `fire-text`, bold, small, sits between the label and the input. The input points to it with `aria-describedby`.
- **Input row:** An input and a secondary button share one edge (the button overlaps by 1px).

### Gatehouse panel
- **Corner Style:** Square.
- **Background:** `panel`, with a 1px `line` border on desktop. On a refusal the border turns fire red.
- **Shadow Strategy:** None (see Elevation & Depth).
- **Internal Padding:** 2rem on top and the sides, 1.5rem at the foot.
- **Content:** The task, one help line, and the development build note. The note is above a 1px rule, in note size and muted ink.

### Gate plaque
The signature component. It does the job of the old origin plate.
- **Label:** A short phrase that reads into the host ("You are at the gate of", "You are signed in at"). Muted ink, 0.8125rem, weight 600, uppercase, tracking 0.12em. This style belongs to the plaque label only.
- **Host:** The tenant host in mono host type, for example `acme.localhost:7299`. It wraps anywhere.
- **Check line:** "Check that your address bar shows the same host." Muted ink, small size. Every plaque carries this line.

### Problem box
- **Style:** Square, 1px fire border, `fire-tint` fill, padding 1rem by 1.25rem. A 24px alert icon in `fire-text` sits at the start and spans two rows.
- **Content:** The title "There is a problem" in `fire-text`, weight 800, then the message. When the message is about a field, it is a link to that field.
- **Behavior:** `role="alert"`. The page moves focus to the box.

### Fact box
- **Style:** Square, 1px `line` border, `field` fill, padding 1rem by 1.25rem.
- **Content:** A label in note size and muted ink, then the value in mono value type. An optional meta line (for example, the App ID) is in note size.
- **Error code variant:** The label and the code sit on one line. The code is in `fire-text`, bold.

### Scope list
Rows divided by a 1px `line` rule. Each row has a frost icon, the plain sentence, and the raw scope name in mono at note size and muted ink. An unknown scope shows its raw name in code style.

### Motion switch
- **Style:** A toggle button labeled "Motion", 44px tall, muted ink, weight 600, small size. The track is a 32 by 16px square outline with a 10px square knob.
- **On:** The track fills with frost and the knob moves 16px to the right in `on-act`.
- **Hover:** The text goes to ink, and a 1px `line` border appears.
- **State:** `aria-pressed` carries the state. The default follows `prefers-reduced-motion`. The choice is stored in `localStorage` under `heimdall.motion`. When storage fails, the choice lasts for the page only.

### The bridge (signature)
An SVG arc of four frost bands (from outside: `bridge-1` to `bridge-4`), an ember thread, and a banked guard band at the outer edge. A sky of 46 fixed stars is behind it. The bridge is `aria-hidden`, because the text says the same state.

| State | Bridge |
|---|---|
| `idle` | Stars twinkle (4.1s to 8.8s cycles). A soft light drifts up each band (11s to 19s). Embers (3 on, 2 off, in a path length of 100) crawl up the ember thread (6s). The banked guard band flickers in steps (3.2s). |
| `busy` | A stream of lights runs up every band (0.8s cycle, each band 0.1s later). The embers crawl faster (1.5s). The busy button carries a 3px running line (1.1s). |
| `refused` | The guard band turns fire red and flares (16, 64, then 44px in 450ms). A refused attempt with a problem box shakes the panel once (420ms). A fire glow burns under the bands (2.4s flicker). The frost dims to 55% brightness. The ember thread turns red. No light moves. |
| `crossing` | Every band lights from the gate to the sky, once (700ms, each band 60ms later). |

On load, the bands draw in from the ground, inner band first, 120ms apart (900ms each). The fire lines light at 620ms. The statement rises 0.35em (600ms), and its fire mark ignites with an overshoot (`ease-back`, at 500ms). On the error page, the statement drops in letter by letter, 40ms apart. The form and the panel never animate in.

With motion off, the scene holds still and the ember thread is solid. The state stays visible: crossing keeps every band lit, and refused keeps the fire.

### Forced colors
In forced-colors mode (Windows High Contrast), the bridge is hidden. Buttons, inputs, the panel, the problem box, and the fact box get a 2px system-color border (`CanvasText`; buttons `ButtonText`). The problem title uses `CanvasText`. Focus uses `Highlight`. The "on" track of the motion switch fills with `Highlight`.

## Do's and Don'ts

### Do:
- **Do** use frost for the bridge and Heimdall's actions, ember for the fire at rest and keyboard focus, and fire red for a refusal only (The One Meaning Rule).
- **Do** show the host on the gate plaque in JetBrains Mono, with the line "Check that your address bar shows the same host."
- **Do** put a plain heading under every figurative statement, and make that heading the `h1`.
- **Do** set the display in Archivo 900 at 86% width, line height 0.86, tracking -0.045em, with a 3em measure on desktop.
- **Do** make every control square and 56px tall (60px for buttons).
- **Do** set the bridge state from the page state, and also say that state in text.
- **Do** keep the motion switch in the first screen. Default it from `prefers-reduced-motion`, and keep the state readable with motion off.
- **Do** give every edge and state a system-color border in forced-colors mode, and hide the bridge there.
- **Do** serve fonts and every other asset from Heimdall's own origin.

### Don't:
- **Don't** use red for anything but a refusal. A busy or unavailable state is not a refusal.
- **Don't** use ember for anything but the bridge's fire, the fire mark, and keyboard focus.
- **Don't** round a corner, add a drop shadow, or add a gradient to a control or a panel.
- **Don't** use JetBrains Mono for prose or headings.
- **Don't** make any state depend on the bridge. Text, focus, and `aria-live` must carry it.
- **Don't** center the task in a card on a gradient.
- **Don't** use this look in a client app. The demo SPA and Huginn are not Heimdall, and the demo SPA keeps its own look in `ui/projects/demo/src/client-kit.css`.
- **Don't** load a font or any other file from a third-party origin.
