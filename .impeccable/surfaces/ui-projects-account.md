---
version: 1
slug: "ui-projects-account"
primary_target: "ui/projects/account"
related_targets: ["ui/projects/demo"]
---

# Account pages (login, consent, error, signed out)

Mode: Operate. The visitor signs in or decides on consent, then leaves. Audience order from PRODUCT.md: reviewers see the rigor; end users sign in fast and can check that the page is real.

Owner delegated the visual choice on 2026-10-19 ("I'll let you choose, make it look great"). No decision page was shown.

## Direction contract

THESIS: The pages read as the issuer's public-service notice: who is asking, which origin you are on, what leaves, and nothing else. It refuses the SaaS sign-in card floating on a gradient with a logo blob.

OWN-WORLD: A public-service identity program. Committed lapis issuer band (#1E2F7A light, #2B3F99 dark) across the top, white page, cool lapis-tinted ground (#EEF1F8) below the column. Square controls with a 2px ink border, 48px tall. Signal-yellow focus (#FFD21F) used for focus only. Fixed state vocabulary: lapis speaks and acts, red refuses, green confirms. System font stack (U8), large body (1.125rem), bold scale steps. Raise (variable-font specimen): hierarchy by scale contrast alone; no card, box, or shadow ranks content. Raise (timetable slide rack): each state color has one meaning everywhere. Raise (botanical folio): all four pages keep one frame, column, and heading baseline, so they read as one sequence.

STORY: The visitor sees the origin first, then the one task, then where the browser goes next. They sign in or decide in one step and trust it.

FIRST VIEWPORT: Lapis band, 64px: "Heimdall" wordmark left. Hanging from the band at the column's left edge, the origin plate: a lapis tab with "Signing in to" and the tenant host in monospace, the signature move. Left-aligned column, max 30rem, 48px below the plate: H1 "Sign in", email and password fields, full-width lapis "Sign in" button. Footer line on the tinted ground.

FORM: Public-service identity program, position 3 of 7 on the grounded list. seed:3aca8e390028b009

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Cross-surface reach

The demo SPA uses the same ui-kit tokens with a neutral ink band labeled as a client, so the visitor can see that it is a different site from Heimdall.

## Decisions recorded at the finish review

- The login page does not name the app. The only API that returns the stored request's client (`GET /session/v1/consent`) needs a session. An endpoint that names the client before sign-in would show request details to anyone who holds a `request_id`. The consent page names the app and its redirect host after sign-in.
- Dark theme: page #10142c, ground #0a0d20, link #a9bbff (AA on both and on the dark red tint).
