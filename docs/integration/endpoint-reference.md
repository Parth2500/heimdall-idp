# Endpoint reference

[Documentation home](../documentation.md)

All paths are relative to the tenant's issuer, for example `https://acme.example.com`. Every endpoint needs HTTPS.

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/openid-configuration` | `GET` | Discovery. |
| `/.well-known/jwks.json` | `GET` | Public signing keys. |
| `/oauth/v1/authorize` | `GET` | Starts a user sign-in. |
| `/oauth/v1/token` | `POST` | Issues tokens. |
| `/oauth/v1/userinfo` | `GET`, `POST` | Returns the user's claims. |
| `/oauth/v1/revoke` | `POST` | Revokes a refresh token family. |

## `GET /.well-known/openid-configuration`

Returns the discovery document (OpenID Connect Discovery 1.0). It lists only what Heimdall supports.

```json
{
  "issuer": "https://acme.example.com",
  "authorization_endpoint": "https://acme.example.com/oauth/v1/authorize",
  "token_endpoint": "https://acme.example.com/oauth/v1/token",
  "jwks_uri": "https://acme.example.com/.well-known/jwks.json",
  "userinfo_endpoint": "https://acme.example.com/oauth/v1/userinfo",
  "revocation_endpoint": "https://acme.example.com/oauth/v1/revoke",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
  "code_challenge_methods_supported": ["S256"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "authorization_response_iss_parameter_supported": true
}
```

- Caching: `Cache-Control: public, max-age=600` by default, and a strong `ETag`. Send `If-None-Match` to get `304`.
- CORS: every origin may read it.
- The document has no `scopes_supported` or `claims_supported`. Your registration lists your scopes.

## `GET /.well-known/jwks.json`

Returns the tenant's public keys (RFC 7517). Each key is an RSA key with `kid`. The set holds the active key, the next key, and recently retired keys.

- Caching: the same as discovery.
- CORS: every origin may read it.
- See [Validate access tokens](validate-access-tokens.md#get-and-cache-the-keys) for the refetch rules.

## `GET /oauth/v1/authorize`

Starts the authorization code flow. The browser calls it, not your server.

| Parameter | Required | Notes |
|---|---|---|
| `response_type` | Yes | `code` only. |
| `client_id` | Yes | |
| `redirect_uri` | If more than one is registered | Exact match. |
| `scope` | Yes | At least one scope. Each one must be registered for the client. |
| `code_challenge` | Yes | `BASE64URL(SHA256(code_verifier))`. |
| `code_challenge_method` | Yes | `S256` only. |
| `state` | No (recommended) | At most 512 characters. |
| `nonce` | No (recommended) | At most 512 characters. Copied into the ID token. |
| `prompt` | No | `none` or `login`. One value only. |
| `max_age` | No | Seconds, as a non-negative integer. |
| `response_mode` | No | `query` only. |
| `request`, `request_uri` | Not supported | Heimdall refuses them. |

Success: `302` to `redirect_uri` with `code`, `state`, and `iss`. The code is valid for 5 minutes and for one use.

Error: `302` to `redirect_uri` with `error`, `state`, and `iss`. Or a Heimdall error page when the client or the redirect URI is not valid. See [Errors and rate limits](errors-and-limits.md#authorization-errors).

Rate limit: 120 requests each minute for each IP address.

## `POST /oauth/v1/token`

Issues tokens. Rules for every request:

- `Content-Type: application/x-www-form-urlencoded`. A `charset` parameter must be `utf-8`. Heimdall refuses every other charset.
- No query string.
- No repeated parameter. Heimdall compares parameter names without case, so `grant_type` and `GRANT_TYPE` are the same name.
- No NUL character in a name or a value.
- Body at most 16 KiB.
- A confidential client authenticates with HTTP Basic (`client_secret_basic`). A public client sends `client_id` in the body (`none`).
- `client_secret` in the body is refused.
- An optional `DPoP` header carries a DPoP proof. At most one. A client registered with `dpop_bound_access_tokens` must send it. See [DPoP](dpop.md).

### `grant_type=authorization_code`

| Parameter | Required | Notes |
|---|---|---|
| `code` | Yes | From the callback. |
| `code_verifier` | Yes | The value behind `code_challenge`. |
| `redirect_uri` | If more than one is registered | The same value as at `/authorize`. |
| `client_id` | Public clients | |
| `resource` | No | The audience. See [Choose the audience](sign-in-users.md#choose-the-audience). |

### `grant_type=refresh_token`

| Parameter | Required | Notes |
|---|---|---|
| `refresh_token` | Yes | Single use. The response has a new one. |
| `scope` | No | Same or smaller than the original grant. |
| `client_id` | Public clients | |
| `resource` | No | The audience of the new access token. |

### `grant_type=client_credentials`

| Parameter | Required | Notes |
|---|---|---|
| `scope` | No | Default: every scope registered for the client. No user scopes. |
| `resource` | If more than one audience is registered | The audience. |

### Response

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid email offline_access",
  "refresh_token": "8xLOxBtZp8...",
  "id_token": "eyJ..."
}
```

| Member | Present when |
|---|---|
| `access_token`, `token_type`, `expires_in` | Always. `token_type` is `DPoP` when the request had a valid proof, else `Bearer`. |
| `scope` | The granted scope is not empty. |
| `refresh_token` | `authorization_code` with `offline_access` and the `refresh_token` grant, or any `refresh_token` request. |
| `id_token` | `authorization_code` with `openid`. Never on refresh. |

Headers: `Cache-Control: no-store` and `Pragma: no-cache`.

CORS: client origins of public clients only. The `DPoP` request header is allowed.

## `GET` or `POST /oauth/v1/userinfo`

Returns the user's claims (OpenID Connect Core, section 5.3).

- Send the access token in `Authorization: Bearer <token>`. A token in the query string gets `400`.
- The token's `aud` must be `<issuer>/oauth/v1/userinfo`.
- The token's scope must have `openid`.

```json
{
  "sub": "0199f0a2-7c1e-7b3a-9d2f-5e8a1c4b6d70",
  "email": "alice@example.com",
  "email_verified": false
}
```

| Claim | Released by |
|---|---|
| `sub` | `openid`. Always present. It equals `sub` in the ID token. |
| `email`, `email_verified` | `email`. `email_verified` is always `false` at this time. |

Heimdall reads the user on each call. A disabled user gets `401` `invalid_token`, even with an unexpired token.

CORS: client origins of public clients only.

## `POST /oauth/v1/revoke`

Revokes a refresh token family (RFC 7009). The form and client authentication rules are the same as at `/token`.

| Parameter | Required | Notes |
|---|---|---|
| `token` | Yes | The refresh token. |
| `client_id` | Public clients | |
| `token_type_hint` | No | Ignored. |

Response: `200` with an empty body, for any token, after successful client authentication. An error only for a malformed request (`400`) or failed client authentication (`401`).

CORS: client origins of public clients only.
