# Concepts

[Documentation home](../documentation.md)

This page defines the terms that the other pages use. The full glossary is in the [threat model](../threat-model.md#glossary).

## Tenants and issuers

One Heimdall installation hosts many tenants. A tenant has its own users, clients, signing keys, and settings.

Each tenant has its own host name. The host name sets the issuer:

```
https://<tenant host>
```

For example, the tenant on `acme.example.com` has the issuer `https://acme.example.com`. The development tenant has the issuer `https://acme.localhost:7200`.

These rules follow from that:

- Your client belongs to exactly one tenant. A `client_id` from one tenant does not work on another tenant.
- Each tenant has its own JWKS. A token from one tenant does not pass the signature check of another tenant.
- Heimdall accepts HTTPS only. A plain HTTP request gets an error.
- An unknown host name gets `404`.

## Client types

| Type | Example | Secret | Authentication at `/token` |
|---|---|---|---|
| Public client | A single-page app, a mobile app | None | `client_id` in the form body (`none`). |
| Confidential client | A server app, a backend-for-frontend (BFF), a service | Yes | HTTP Basic with the client ID and secret (`client_secret_basic`). |

A public client cannot keep a secret. Code in a browser or on a phone is visible to its user. PKCE protects its codes instead.

A confidential client keeps its secret on a server. It also uses PKCE, because OAuth 2.1 requires PKCE for every client.

## Grants

| Grant | Use it when | Client types |
|---|---|---|
| `authorization_code` | A user signs in to your app. | Public and confidential. |
| `refresh_token` | Your app needs a new access token while the user is away from Heimdall. | Public and confidential. |
| `client_credentials` | A service calls an API for itself, with no user. | Confidential only. |

The operator turns on each grant for each client. A grant that is not turned on gets `unauthorized_client`.

## Tokens

| Token | Format | Audience (`aud`) | Lifetime (default) | Who reads it |
|---|---|---|---|---|
| Code | Opaque string | Not applicable | 5 minutes, single use | Heimdall only. |
| Access token | JWT, `typ` = `at+jwt` (RFC 9068) | One resource server, or the userinfo endpoint | 5 minutes | The resource server. Your client must not parse it. |
| ID token | JWT, `typ` = `JWT` | Your `client_id` | Same as the access token | Your client. |
| Refresh token | Opaque string | Not applicable | 7 days idle, 30 days absolute | Heimdall only. |

The operator can change the access token lifetime from 1 to 60 minutes. The operator can change the refresh token lifetimes from 1 hour to 90 days. Read `expires_in` in the token response. Do not hard-code a lifetime.

Heimdall signs every JWT with RS256. The `kid` header names the key in the JWKS.

## Scopes

| Scope | Effect |
|---|---|
| `openid` | Heimdall issues an ID token. The access token can read `/userinfo`. |
| `email` | `/userinfo` releases `email` and `email_verified`. |
| `offline_access` | Heimdall issues a refresh token. The client must have the `refresh_token` grant. |
| Other values | API scopes that the operator registers for your client, for example `orders.read`. Heimdall copies them into the `scope` claim of the access token. |

Heimdall does not reduce a scope request. If you ask for a scope that your client does not have, Heimdall refuses the whole request with `invalid_scope`.

`email_verified` is always `false` at this time. Heimdall does not verify email addresses yet. Do not use the email address as the user's identifier. Use `sub` with `iss`.

## Audiences

An access token has exactly one audience. The audience is the resource server that may accept the token.

- A user grant can always ask for the userinfo endpoint (`<issuer>/oauth/v1/userinfo`) as the audience.
- Any other audience must be registered for your client.
- Your client chooses the audience with the `resource` parameter (RFC 8707) at `/token`.

[Sign in users](sign-in-users.md#choose-the-audience) explains the default when you leave out `resource`.

## The user identifier

The `sub` claim identifies the user. It is a stable value inside one tenant. Store the pair (`iss`, `sub`) as the key of the user in your app. Do not use `email`, because a user can change it.

In a `client_credentials` token, `sub` is the `client_id` of the service, not a user.
