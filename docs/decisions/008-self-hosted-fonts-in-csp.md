# DR-008: The account pages may load fonts from Heimdall's own origin

- Date: 2026-10-23
- Status: Accepted. Approved by the owner with U15.
- Affects: N5 and U8 in the front-end design.

## Before

The pages used no web font. The CSP allowed no font source.

## After

The CSP of the account pages allows `font-src 'self'`. The font files are in the repository. The pages never load a font from a font service.

## Reason

The design needs its fonts. A font from the same origin adds no third-party origin, so a font service cannot track users or change the files.

## Consequences

The files are about 130 KB and have a content hash in each name, so the browser caches them for a year.
