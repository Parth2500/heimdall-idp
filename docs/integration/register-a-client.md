# Register a client

[Documentation home](../documentation.md)

Heimdall has no self-service registration yet. The Heimdall operator registers each client. A later release adds an admin portal for this task.

## What to give the operator

| Item | Example | Notes |
|---|---|---|
| Tenant | `acme.example.com` | The tenant of your users. |
| Client name | `Orders web app` | Users can see it. |
| Client type | Public or confidential | See [Concepts](concepts.md#client-types). |
| Grants | `authorization_code`, `refresh_token` | Ask only for the grants that you use. |
| Redirect URIs | `https://orders.example.com/callback` | Each URI that your app uses. See the rules below. |
| Scopes | `openid email offline_access orders.read` | Each scope that your app can ask for. |
| Audiences | `https://api.orders.example.com` | Each resource server that your access tokens are for. Leave it empty if you only call `/userinfo`. |
| DPoP | Optional or required | With `dpop_bound_access_tokens`, `/token` refuses a request without a DPoP proof. See [DPoP](dpop.md). |
| Consent | On or off | With consent on, the user approves each sign-in request on a Heimdall page. First-party apps usually turn it off. |
| Post-logout redirect URIs | `https://orders.example.com/signed-out` | Where Heimdall may send the browser after a sign-out. The redirect URI rules apply. See [Sign out](sign-out.md). |
| Pushed authorization requests | Optional or required | With `require_pushed_authorization_requests`, `/authorize` takes this client's requests only through PAR. See [Pushed authorization requests](par.md). |
| Resource audiences | `https://api.orders.example.com` | Confidential clients only. The audiences that your server serves. It may introspect access tokens for them. |
| Back-channel logout URI | `https://orders.example.com/backchannel-logout` | Optional. Your server endpoint for a `logout_token`. It must use `https` on a public address. |

## What you get back

- A `client_id`.
- For a confidential client, a client secret. The operator sees the secret only once. Heimdall stores only its hash, so nobody can show it again. Keep it in a secret store, not in source control.
- The issuer URL of the tenant.

## Redirect URI rules

Heimdall compares redirect URIs by exact string match (RFC 9700). These rules apply when the operator registers a URI:

- The URI must be absolute.
- The URI must use `https`. Plain `http` is allowed only for a loopback address, for example `http://localhost:4200/callback` or `http://127.0.0.1:8080/callback`.
- The URI must not contain a wildcard (`*`).
- The URI must not contain a fragment (`#...`).
- The URI must not contain user information (`user:password@`).

Exact match means exact. `https://app.example.com/callback` and `https://app.example.com/callback/` are two different URIs. A different port, a different case in the path, or an extra query parameter also makes a different URI. Register each one that you use.

## Browser access (CORS)

A browser app reads the responses of `/token`, `/revoke`, and `/userinfo` from another origin. Heimdall allows this read only for an active public client. Heimdall takes the allowed origins from the client's `https` redirect URIs.

For example, the redirect URI `https://orders.example.com/callback` allows the origin `https://orders.example.com`. You do not register origins on their own.

A confidential client gets no CORS access. Its server calls Heimdall, not the browser.

Discovery and JWKS allow every origin, because they are public.

## Rotate a client secret

A client can have two valid secrets at the same time. This overlap lets you rotate a secret with no downtime:

1. Ask the operator for a new secret. The old secret stays valid.
2. Deploy the new secret to every server of your app.
3. Ask the operator to revoke the old secret.
