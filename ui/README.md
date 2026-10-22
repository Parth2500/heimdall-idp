# Heimdall UI

One Angular workspace (U1 in `docs/frontend-design.md`). It holds the `account` application (the Heimdall login, consent, error, and signed-out pages), the `demo` application (a sample client), and the `ui-kit` library (design tokens and the page frame, U13).

## Setup

Use Node.js 24 (`.nvmrc`). Install without install scripts (U8):

```sh
npm ci --ignore-scripts
```

## Commands

| Command               | What it does                                                                          |
| --------------------- | ------------------------------------------------------------------------------------- |
| `npm start`           | Serves the demo SPA on `https://demo.localhost:4300`, with a self-signed certificate. |
| `npm test`            | Runs the unit tests once (Vitest).                                                    |
| `npm run build`       | Builds the demo SPA with subresource integrity.                                       |
| `npm run lint:format` | Checks the formatting (Prettier).                                                     |

## Demo SPA against Heimdall

1. Run `seed-dev` (see the root README). It registers the public client `demo-spa` and prints the password of `alice@acme.localhost` once.
2. Build the account pages: `npm run build` or `npm run watch:account`.
3. Run Heimdall with the `https` launch profile, then `npm start`.
4. Open `https://demo.localhost:4300` and accept the development certificates of both origins.

## Dependency overrides

`package.json` has one override. Remove it when it is no longer needed.

| Override                            | Reason                                                                                                                                                                                                                               | Remove when                                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| `vite` 8.3.4 under `@angular/build` | `@angular/build` 22.2.3 pins `vite` 8.3.0, which has six advisories (GHSA-9jrq-w75r-8gcw, GHSA-rq7h-c2jc-7f22, GHSA-vfpm-58rq-9qcg, GHSA-r825-w8mm-5pxw, GHSA-587h-7wmj-h5pm, GHSA-698v-4r3x-3vcv). They affect the dev server only. | A release of `@angular/build` depends on `vite` 8.3.3 or later. |
