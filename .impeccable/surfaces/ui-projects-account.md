---
version: 1
slug: "ui-projects-account"
primary_target: "ui/projects/account"
related_targets: []
---

# Account pages (login, consent, error, signed out)

Mode: Operate. The visitor signs in or decides on consent, then leaves. Audience order from PRODUCT.md: reviewers see the rigor; end users sign in fast and can check that the page is real.

On 2026-10-23 the owner replaced the public-service direction (old U13) with "Burning Bridge", drawn by the owner with Claude in Figma (file AU29OEocRwDxMPMu3Dk6ZD). The owner asked the build to go beyond the comp. Confirmed answers: night and day themes from the OS setting; a full scene (stars, shimmer) that reacts to state, with a visible switch that stops motion; the demo SPA is not Heimdall and is out of scope (it keeps the old look on its own stylesheet).

## Direction contract

THESIS: Heimdall guards Bifröst. Each page is the gate at the foot of the burning bridge: the host you stand at, one decision, and a bridge that shows the state of the crossing. It refuses the centered SaaS card on a gradient.

OWN-WORLD: Night ground #07080d with a few cold stars. Day: dawn ground, same bridge in deeper lapis. The bridge is concentric frost bands (#4c6fff, #2b3f99, #1e2f7a, #14205a) with an ember thread (#ff7a45) at rest. Guard-fire red (#e5372b) appears only on a refusal. A square, flat gatehouse panel (#10121c, 1px line) holds the controls. Archivo, self-hosted, heavy and tight for display; JetBrains Mono, self-hosted, for hosts and codes. Square controls, 56px tall.

STORY: The visitor reads the host on the gate plaque, does one task in the panel, and sees the bridge answer: light runs while Heimdall checks, fire flares on a refusal, the bridge lights when they cross.

FIRST VIEWPORT: Desktop: wordmark and motion switch on a top line. Left column: a huge two-line display ("Sign in."), the gate plaque at the bottom left with the host in mono and the address bar check. Right: the gatehouse panel, vertically centered, with the primary action full width. The bridge rises from the bottom middle behind the panel to the right edge. Phone: the bridge is a corner arc, the display shrinks, the plaque sits above the form, and the button is inside a 390x667 viewport.

FORM: Burning Bridge, pinned by the owner. The roll ran for the record; a pinned direction beats it, so its assignment was not built. seed:b22d44c3dbc5ba92

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

Signature interaction: the bridge is state. Idle: stars twinkle, a slow light drifts along the bands. Busy: a light runs up the bands in sequence. Refused: the outer band flares into guard fire and stays red while the problem shows. Crossing (success): every band lights. The motion switch and prefers-reduced-motion stop all of it; state stays readable from color and text alone.

## Cross-surface reach

None. The demo SPA and Huginn are clients, not Heimdall, and must not wear Heimdall's look.

## Decisions recorded at the finish review

- The login page does not name the app. The only API that returns the stored request's client (`GET /session/v1/consent`) needs a session. An endpoint that names the client before sign-in would show request details to anyone who holds a `request_id`. The consent page names the app and its redirect host after sign-in.
