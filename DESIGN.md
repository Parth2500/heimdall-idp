---
name: Heimdall
description: The account pages and demo client of the Heimdall identity provider, in a public-service identity program.
colors:
  lapis: "#1e2f7a"
  lapis-strong: "#14205a"
  link: "#1e2f7a"
  on-lapis: "#ffffff"
  on-lapis-muted: "#c9d1f0"
  client: "#2b2e36"
  client-strong: "#1c1e24"
  ink: "#0b0c14"
  ink-muted: "#474d63"
  page: "#ffffff"
  ground: "#eef1f8"
  rule: "#c7cddf"
  focus: "#ffd21f"
  focus-ink: "#0b0c14"
  red: "#b3261e"
  red-tint: "#fbeae8"
  green: "#0b6b3a"
  green-tint: "#e5f3ea"
  lapis-dark: "#2b3f99"
  lapis-strong-dark: "#3a50b5"
  link-dark: "#a9bbff"
  on-lapis-muted-dark: "#d3daf5"
  client-dark: "#3a3e48"
  client-strong-dark: "#4a4f5b"
  ink-dark: "#e9ecf7"
  ink-muted-dark: "#aab2cc"
  page-dark: "#10142c"
  ground-dark: "#0a0d20"
  rule-dark: "#333a5c"
  red-dark: "#ff8a80"
  red-tint-dark: "#3a1618"
  green-dark: "#74d6a0"
  green-tint-dark: "#0f2e20"
typography:
  display:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "clamp(2rem, 1.6rem + 1.6vw, 2.75rem)"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 700
    lineHeight: 1.25
  wordmark:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "-0.01em"
  body:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 400
    lineHeight: 1.55
    fontFeature: "tnum"
  label:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
    lineHeight: 1.55
  hint:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
  small:
    fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
  mono:
    fontFamily: "ui-monospace, 'SF Mono', 'Cascadia Mono', 'DejaVu Sans Mono', 'Liberation Mono', Menlo, Consolas, monospace"
    fontSize: "1em"
    fontWeight: 400
rounded:
  none: "0px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "6": "24px"
  "8": "32px"
  "12": "48px"
  "16": "64px"
  band-height: "64px"
  control: "48px"
  border: "2px"
  column: "30rem"
  column-wide: "48rem"
  frame: "64rem"
components:
  button-primary:
    backgroundColor: "{colors.lapis}"
    textColor: "{colors.on-lapis}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "8px 24px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "{colors.lapis-strong}"
    textColor: "{colors.on-lapis}"
  button-secondary:
    backgroundColor: "{colors.page}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "8px 24px"
    height: "48px"
  button-secondary-hover:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.ink}"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.on-lapis}"
    rounded: "{rounded.none}"
    padding: "4px 12px"
  input:
    backgroundColor: "{colors.page}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.none}"
    padding: "8px 12px"
    height: "48px"
  problem-box:
    backgroundColor: "{colors.red-tint}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "16px 24px"
  confirm-box:
    backgroundColor: "{colors.green-tint}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "16px 24px"
  note-box:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "16px 24px"
  band-issuer:
    backgroundColor: "{colors.lapis}"
    textColor: "{colors.on-lapis}"
    typography: "{typography.wordmark}"
    height: "64px"
  band-client:
    backgroundColor: "{colors.client}"
    textColor: "{colors.on-lapis}"
    typography: "{typography.wordmark}"
    height: "64px"
  origin-plate:
    backgroundColor: "{colors.lapis}"
    textColor: "{colors.on-lapis}"
    padding: "12px 16px 16px"
  footer:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.ink-muted}"
    typography: "{typography.small}"
    padding: "24px 0"
---

# Design System: Heimdall

## Overview

**Creative North Star: "The Public-Service Notice"**

Each page reads as a notice from the issuer. It states who asks, which origin the browser is on, what leaves, and nothing else. The world is a public-service identity program, like a government design system. A committed lapis band runs across the top. A white page carries one left-aligned column. A cool, lapis-tinted ground closes the page below the column.

Hierarchy comes from scale and weight only. Body text is large (1.125rem). Headings step up in bold. No card, panel, or shadow ranks content. Boxes appear only to carry a state: a refusal, a confirmation, or a neutral note. Controls are square, with a 2px ink border and a height of 48px.

Every page uses one frame: the band, the origin plate, the column, and the footer. The login, consent, error, and signed-out pages keep the same frame, column, and heading baseline. So they read as one sequence. The demo client uses the same frame with a neutral band, so the user can see that it is a different site. Every page states that Heimdall is a development build.

**Key Characteristics:**
- A lapis issuer band (64px) with the wordmark "Heimdall" at the left.
- An origin plate hangs from the band and shows the current host in monospace.
- A white page with a left-aligned column (30rem), and a tinted ground for the footer.
- Square controls: 2px border, 48px tall, no radius anywhere.
- A fixed state vocabulary: lapis speaks and acts, red refuses, green confirms, yellow marks focus.
- The system font stack only. No web font and no third-party origin (U8).
- Light and dark themes from `prefers-color-scheme`.

## Colors

The palette is one committed blue, cool neutrals, and three state colors. Each color has one meaning everywhere.

### Primary
- **Issuer Lapis** (lapis; dark theme lapis-dark): The band, the origin plate, primary buttons, and text selection. Lapis means "Heimdall speaks or acts". Hover moves to **Deep Lapis** (lapis-strong). In the dark theme, the hover color is lighter than the base, so the change stays visible.
- **Link Lapis** (link; dark theme link-dark): Inline links. In light mode it equals Issuer Lapis. In dark mode it is a pale lapis that keeps AA contrast on the page, the ground, and the red tint.
- **On-Lapis White** (on-lapis) and **On-Lapis Mist** (on-lapis-muted): Text on the band and the plate. Mist is for the plate label and the hover underline of band navigation.

### Secondary
- **Client Slate** (client, client-strong): The band and plate of a client application, such as the demo SPA. Slate tells the user "this is not Heimdall". It replaces lapis only in the frame.

### Tertiary
- **Signal Yellow** (focus) with **Focus Ink** (focus-ink): Keyboard focus only. The yellow field reads on lapis, on white, and on the dark page.
- **Refusal Red** (red) on **Red Tint** (red-tint): Errors, refusals, and invalid fields.
- **Confirmation Green** (green) on **Green Tint** (green-tint): A done or confirmed result.

### Neutral
- **Ink** (ink): Body text, headings, control borders, and the table header rule.
- **Muted Ink** (ink-muted): Hints, footnotes, fact labels, and footer text. It still passes 4.5:1 on the page and on the ground.
- **Page White** (page): The sheet behind the column, and the fill of inputs and secondary buttons.
- **Lapis Ground** (ground): The footer, the note box, the hover fill of secondary buttons, and the body background.
- **Hairline** (rule): 1px dividers in lists, tables, and the footer top edge.

### Named Rules
**The One Meaning Rule.** Each state color means one thing on every page. Lapis speaks or acts. Red refuses or fails. Green confirms. Yellow marks keyboard focus and nothing else.

**The Tokens Not Components Rule.** Tenant branding (Phase 3) changes token values. It never changes a component.

## Typography

**Display Font:** system-ui (with -apple-system, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif)
**Body Font:** the same system stack
**Label/Mono Font:** ui-monospace (with SF Mono, Cascadia Mono, DejaVu Sans Mono, Liberation Mono, Menlo, Consolas, monospace)

**Character:** One plain sans family at every level. Weight and size carry the hierarchy. The monospace face marks values that a machine compares, such as hosts, client IDs, scope names, error codes, and token fingerprints.

The system stack is a security constraint, not a style preference. Decision U8 forbids web fonts and third-party origins on the login page.

### Hierarchy
- **Display** (700, clamp(2rem, 1.6rem + 1.6vw, 2.75rem), 1.1, -0.02em): The one page title, such as "Sign in". Balanced wrap.
- **Headline** (700, 1.5rem, 1.25): Section headings inside a page, such as "Theft demo".
- **Wordmark** (800, 1.5rem, 1, -0.01em): The name in the band. It is the only 800 weight.
- **Body** (400, 1.125rem, 1.55): All running text. Tabular numerals are on. Lead text and prose keep a measure of 34em.
- **Label** (700, 1.125rem): Field labels, message box titles, and table captions.
- **Hint** (400, 1rem): Field hints, field errors (700, red), and table text.
- **Small** (400, 0.875rem): Footnotes, fact labels, the plate label, and the footer.
- **Mono** (inherits size, font-size-adjust 0.53): Machine values. The plate host uses mono at 1.125rem, 700.

### Named Rules
**The Scale Contrast Rule.** Size and weight rank content. A heading never gets a box, a color, or a rule to look important.

**The Machine Value Rule.** Monospace marks only values that a user or a machine compares character by character. Prose never uses mono.

## Layout

The frame centers a 64rem track with 16px gutters. The column inside it is left-aligned and has a maximum width of 30rem. The demo client uses a wide column of 48rem for tables; its prose keeps the 34em measure.

The band is 64px tall. The origin plate hangs from the band at the left edge of the column. The page content starts 48px below the plate. The sheet ends with 64px of space. The footer sits on the ground, with 24px of padding above and below.

Spacing follows a 4px rhythm (4, 8, 12, 16, 24, 32, 48, 64px). A page stack separates blocks by 24px. A tight stack separates a heading from its list by 12px. A field separates its label, error, and input by 8px. In the demo, a new section starts 48px below the last one, and a table starts 32px below its lead text.

The layout has one column at every width. No breakpoint changes the structure. The column and the frame shrink with the viewport, and long hosts wrap at any character.

### Named Rules
**The One Frame Rule.** Every page uses the same band, plate, column, and footer. A new page changes the content of the column, never the frame.

## Elevation & Depth

The system is flat. No surface casts a shadow, and no surface floats over another. Depth comes from three tonal planes: the lapis band, the white sheet, and the tinted ground. The only `box-shadow` in the system is part of the focus indicator: a yellow ring with a 6px ink underline below the control. Links get a yellow field with a 4px ink underline.

### Shadow Vocabulary
- **Focus field** (`box-shadow: 0 0 0 3px var(--hd-focus), 0 6px 0 0 var(--hd-focus-ink)`, with a 3px yellow outline): Every focus-visible control.
- **Link focus** (`box-shadow: 0 -2px var(--hd-focus), 0 4px var(--hd-focus-ink)` on a yellow background): Every focus-visible link.

### Named Rules
**The Flat Notice Rule.** Surfaces stay flat in every state. A shadow appears only as part of keyboard focus.

## Shapes

Every corner is square (0px). Controls have a 2px border. An invalid input changes to a 4px red border and keeps its outer size. Message boxes have a full 2px border in their state color, or a 1px hairline for a neutral note. Dividers are 1px hairlines. The table header rule is 2px ink.

The one non-rectangular shape is the origin plate. Its bottom edge has a shallow notch: `clip-path: polygon(0 0, 100% 0, 100% 100%, 50% calc(100% - 0.5rem), 0 100%)`. The plate looks like a ribbon tab that hangs from the band.

### Named Rules
**The Square Corner Rule.** No element has a border radius. The plate notch is the only shaped edge.

## Logo

The watcher's eye: an open eye with a keyhole pupil. It watches, and it grants access. The brand book, the four SVG files and the tokens are in [`docs/brand/`](docs/brand/README.md).

- **Files:** `heimdall-mark.svg` is the favicon and app icon. `heimdall-mark-dark.svg` is the dark variant. `heimdall-eye-on-lapis.svg` goes in the band. `heimdall-eye-ink.svg` is for one-ink use.
- **The band:** the eye is 32px and sits 12px (`space-3`) before the wordmark. `HdFrame` draws it for the issuer tone only.
- **The Client Band Rule:** a client band never carries the eye. A client is not Heimdall.
- **The tile:** the tile is square. The Square Corner Rule applies to the logo.
- **Colours:** use lapis and white, or ink alone. Do not use Signal Yellow, red or green on the logo. Each of these colours has one other meaning.
- **Minimum size:** 16px. Below 16px, the keyhole disappears.
- **Never** round the tile, add a gradient, glow or shadow, or put the eye on a client's band or plate.

## Components

### Buttons
Plain, firm, and square.
- **Shape:** square corners (0px), 2px border, minimum height 48px.
- **Primary:** Issuer Lapis fill and border, white bold text, 8px by 24px padding. A form's submit button fills the column width.
- **Hover / Focus:** Hover changes the fill and border to Deep Lapis in 120ms (cubic-bezier(0.16, 1, 0.3, 1)). Focus shows the yellow focus field.
- **Secondary:** Page White fill, ink text, 2px ink border. Hover fills with Lapis Ground. Use it for the second choice, such as "Deny", and for "Show" in the password row.
- **Quiet:** Transparent, inherits the text color, border in the current color, 4px by 12px padding, weight 600. Hover underlines the text. Use it in the band, such as "Sign out" in the demo.
- **Busy:** A busy button gets `aria-disabled`, opacity 0.7, and the progress cursor. Its label changes, for example "Signing in".
- **Paired:** A button attached to an input overlaps the input border by 2px, so the two share one edge.

### Chips
- **Status mark (demo):** A small inline box with a 2px border in the current color, 0.875rem bold text, and 8px side padding. Red reads "Refused". Green reads "Issued". It follows the One Meaning Rule.

### Cards / Containers
There are no cards. Three message boxes carry state only.
- **Corner Style:** square (0px).
- **Problem box:** 2px red border, Red Tint fill, red bold title "There is a problem". It takes focus when it appears.
- **Confirm box:** 2px green border, Green Tint fill, green bold title.
- **Note box:** 1px hairline border, Lapis Ground fill, for a neutral status.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Internal Padding:** 16px by 24px.

### Inputs / Fields
- **Style:** Page White fill, 2px ink border, square, minimum height 48px, 8px by 12px padding, body size text. The label is bold and sits above the input. A hint or an error sits between the label and the input.
- **Focus:** the yellow focus field with the ink underline.
- **Error:** The border changes to 4px red. A bold red message above the input starts with the hidden word "Error:".

### Navigation
- **Band navigation (demo):** Links in On-Lapis White, weight 600, no underline. Hover shows a 3px Mist bottom border. The active page shows a 3px white bottom border and `aria-current="page"`. The links wrap on narrow screens.
- **Inline links:** Link Lapis with a 1px underline at 0.2em offset. Hover thickens the underline to 3px.

### Lists and Tables
- **Rule list:** No bullets. A hairline above the list and below each item. 16px vertical padding for each item.
- **Table:** Full width, 1rem text, left-aligned, no vertical rules. A 2px ink rule below the header. Hairlines between rows. The caption is bold and left-aligned.

### Origin Plate (signature component)
A lapis tab hangs from the band at the left edge of the column. A small Mist label names the relation, such as "Signing in to" or "You are on". Below it, the current host shows in bold monospace at 1.125rem. The host is the same value as the address bar, so the user can compare the two and see a phishing copy. In a client app, the plate uses Client Slate and the label names the app as a Heimdall client.

### Band and Busy Line
The band holds the wordmark at the left and optional controls at the right. When a page waits for the server, a 3px white line moves across the bottom edge of the band (1.1s, the ease-out curve, repeated). It is the only authored animation. Reduced motion stops it.

## Do's and Don'ts

### Do:
- **Do** put every new page inside the one frame: band, origin plate, column, footer.
- **Do** rank content with size and weight: Display for the page title, Headline for sections, Body at 1.125rem.
- **Do** keep controls square, with a 2px border and a height of 48px.
- **Do** use lapis for Heimdall and its actions, red for a refusal, green for a confirmation, and yellow for focus only.
- **Do** show machine values (hosts, IDs, scopes, error codes) in monospace.
- **Do** use the client band and plate color for any site that is not Heimdall.
- **Do** keep text at 4.5:1 contrast or more in both themes.
- **Do** state on every page that Heimdall is a development build, until the owner decides otherwise.

### Don't:
- **Don't** add a web font or load anything from a third-party origin (U8).
- **Don't** use a card, a panel, or a shadow to rank content. A box carries a state only.
- **Don't** use yellow for anything except keyboard focus.
- **Don't** give a state color a second meaning, for example green for a brand accent.
- **Don't** round a corner. The plate notch is the only shaped edge.
- **Don't** mark a message with a thick side stripe. A message box has a full border.
- **Don't** add a small label above a page title. The title stands alone.
- **Don't** change a component for tenant branding. Change tokens only.
