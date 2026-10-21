# Refresh tokens

[Documentation home](../documentation.md)

A refresh token lets your client get a new access token without a new sign-in. Heimdall rotates refresh tokens and detects reuse. Read this page before you turn refresh tokens on. A wrong setup signs users out.

## Get a refresh token

Your client needs all of these:

- The `refresh_token` grant, which the operator turns on.
- `offline_access` in the `scope` at `/authorize`.

If you ask for `offline_access` without the grant, Heimdall refuses the request with `invalid_scope`.

## Use a refresh token

```http
POST /oauth/v1/token HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=8xLOxBtZp8...
&client_id=orders-web
```

A confidential client sends HTTP Basic instead of `client_id`, as at the code redemption.

Optional parameters:

| Parameter | Effect |
|---|---|
| `scope` | A smaller scope for the new access token. It can never add a scope that the user did not grant. A wider scope gets `invalid_scope`, and your refresh token stays usable. |
| `resource` | The audience of the new access token. The rules are the same as at the code redemption. See [Choose the audience](sign-in-users.md#choose-the-audience). |

The response has a new `access_token` and a new `refresh_token`. It has no new ID token. Keep the ID token from the sign-in.

## Rotation

Each refresh token works **once**. Each use returns a new refresh token. You must replace the old token with the new one at once.

All refresh tokens from one sign-in form a **family**. The family has an absolute lifetime (30 days by default). Rotation does not extend it. When the family ends, the user must sign in again.

The family also has an idle timeout (7 days by default). Each refresh moves the idle limit forward, but never past the absolute lifetime.

## Reuse detection

If anyone presents a refresh token that was already used, Heimdall treats it as theft:

1. Heimdall revokes the whole family at once. The newest refresh token stops working too.
2. Heimdall raises a security alert.
3. The caller gets `invalid_grant`.

There is no grace window. A second use one millisecond later is still reuse. A grace window would give an attacker the same race that reuse detection closes.

### Avoid false reuse

A client bug can look like theft. These rules prevent it:

- **Refresh from one place only.** In a browser app, two tabs that refresh at the same time send the same token twice. One tab wins, and the other tab's request revokes the family. Use a lock across tabs (for example, the Web Locks API), or keep tokens in one tab only.
- **Save the new token before you use it.** If your app crashes after Heimdall rotated the token but before you saved the new one, the next start sends the old token. That is reuse.
- **Do not retry a refresh on a timeout.** The first request may have succeeded. If you retry with the same token, Heimdall sees reuse. Sign the user in again instead.
- **Do not set your library to reuse refresh tokens.** For example, keep `allowUnsafeReuseRefreshToken` at `false` in `angular-auth-oidc-client`.

## Where to store a refresh token

| Client | Storage |
|---|---|
| Server app or BFF | Server-side storage, encrypted at rest. Never send it to the browser. |
| Browser app | Memory only. Do not put it in `localStorage` or `sessionStorage`. Any script on the page can read web storage, so a cross-site scripting bug would leak the token. |

A browser app that keeps tokens in memory loses them on a page reload. After a reload, send the user to `/authorize` again. If the Heimdall session is still valid, the user comes back with no login page. (If your client has consent turned on, the user sees the consent page again. Heimdall does not remember consent yet.) The [Angular recipe](recipes/angular-spa.md) shows this setup.

For the strongest protection in a browser app, use a backend-for-frontend (BFF). The BFF is a confidential client. It keeps the tokens on the server, and the browser gets only a session cookie.

## When a refresh fails

| Response | Meaning | Action |
|---|---|---|
| `400` `invalid_grant` | The token is unknown, expired, used, or revoked. Or the user is disabled. | Delete the token. Sign the user in again. |
| `400` `invalid_scope` | You asked for a scope wider than the grant. | Fix the request. The token is still usable. |
| `401` `invalid_client` | Client authentication failed. | Check the client ID and secret. |
| `429` | Rate limit. | Wait for `Retry-After` seconds. |

## End a refresh token

Revoke the refresh token when the user signs out. Revocation ends the whole family. See [Sign out](sign-out.md).
