# Bruno collection

A [Bruno](https://www.usebruno.com/) collection for manual tests against a local Heimdall (issue #23). Each request has a short note and tests. No browser is needed: the user flow signs in through the session API, and the `/authorize` requests read the code from the `Location` header.

| Folder | Requests |
|---|---|
| `01 Discovery` | The discovery document and the JWKS. |
| `02 Service` | A `client_credentials` token, introspection of that token, and a wrong secret. |
| `03 User sign-in` | Antiforgery token, sign-in, `/authorize` with PKCE, code redemption, `/userinfo`, refresh, refresh token reuse, `/userinfo` after the reuse (D44), and sign-out. |
| `04 PAR, revoke, sign-out` | A pushed request (`/par`), `/authorize` with the `request_uri`, `/revoke`, a refresh with the revoked token, and RP-initiated sign-out. |

## Before you start

1. Run `seed-dev` and start Heimdall (see the README). The collection uses the development clients `demo-service` and `demo-spa`.
2. Open this folder in Bruno and choose the environment `local`.
3. Set the two secret variables. Bruno stores them on your machine, not in these files:
   - `serviceClientSecret`: the `demo-service` secret that `seed-dev` printed.
   - `userPassword`: the password of `userEmail` (by default `alice@acme.localhost`, printed by `seed-dev`).

The development certificate names only `localhost`. In the Bruno app, turn off SSL certificate verification for this collection. Do this only for a local server.

## Run from the command line

```
npx @usebruno/cli@4.2.1 run -r --env local --insecure \
  --env-var serviceClientSecret=<secret> --env-var userPassword=<password>
```

Run it from this folder. `--insecure` is for the local development certificate only. Each run signs in twice, and the sign-in limit is 5 each minute for each IP. The CLI is not a dependency of the repository. Its own dependencies have npm audit findings, so run it only against a local server.

## Rules for new requests

- Keep secrets in `vars:secret` only. Never write a secret, a token, or a password into a `.bru` file.
- Give each request a `docs` block with the reason for the behavior, and tests for the status and the key fields.
- Make a new PKCE verifier, `state`, and `nonce` in a pre-request script for each `/authorize` or `/par` request.
