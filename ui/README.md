# Heimdall UI

One Angular workspace (U1 in `docs/frontend-design.md`). It holds the `demo` application now. The `account` application and the `ui-kit` library come next.

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

The demo signs in at `https://acme.localhost:7200` as the public client `demo-spa`. A full sign-in also needs these server changes from `docs/frontend-design.md`, section 5:

- S1 to S3: the account pages on the tenant origin.
- S4: CORS for the client's origin on `/token`, `/revoke`, and `/userinfo`.
- S6: `seed-dev` registers `demo-spa` with the redirect URI `https://demo.localhost:4300/callback`.
