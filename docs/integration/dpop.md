# DPoP: sender-constrained tokens

DPoP (RFC 9449) binds a token to a key pair that your client holds. A thief who steals the token cannot use it without the private key. Use DPoP for a public client, such as a browser app, because a public client has no secret to protect its refresh token.

Status: Heimdall supports DPoP at `/authorize` (`dpop_jkt`) and at `/token`. Support at `/userinfo` and in discovery is still in progress (issue #17). The [limits](#limits-today) section tells you what that means for you now.

## How it works

1. Your client creates a key pair once, for example in the browser with Web Crypto. Keep the private key non-extractable.
2. For each request to `/token`, your client signs a short JWT, the DPoP proof, with that key. It sends the proof in the `DPoP` header.
3. Heimdall checks the proof. Then it binds the tokens to the key:
   - The access token gets the claim `cnf.jkt`, the thumbprint of your public key (RFC 7638). The response has `"token_type": "DPoP"`.
   - For a public client, the refresh token family is bound too. Each refresh needs a proof from the same key.
4. A request without a proof gets a normal bearer token, unless your client is registered to require DPoP.

## Bind the code too (`dpop_jkt`)

Send the thumbprint of your public key (RFC 7638, base64url, 43 characters) as `dpop_jkt` in the `/authorize` request. Heimdall then binds the authorization code to your key, so the whole flow uses one key, from the first redirect to the last refresh.

- Only a token request with a proof from that key redeems the code.
- A token request without a proof gets `invalid_dpop_proof`. A proof from another key gets `invalid_grant`.
- Neither failure uses the code. A thief who intercepts the code cannot redeem it, and cannot use it up before your client does.
- A malformed `dpop_jkt` gets `error=invalid_request` at your redirect URI.

Most DPoP libraries compute the thumbprint for you. Use the same key pair for `/authorize` and `/token`.

## The proof

The proof is a JWT with this header and these claims. Most DPoP libraries build it for you.

| Part | Value |
|---|---|
| `typ` (header) | `dpop+jwt` |
| `alg` (header) | `ES256` or `RS256`. Heimdall refuses every other algorithm. |
| `jwk` (header) | Your public key only. EC P-256, or RSA with at least 2048 bits. A private key member gets the proof refused. |
| `jti` | A new random value for each proof. Heimdall accepts each value once. |
| `htm` | `POST` |
| `htu` | The token endpoint URL without query or fragment, for example `https://acme.example.com/oauth/v1/token`. |
| `iat` | The current time. Heimdall refuses a proof more than 60 seconds from its own clock. |

Send exactly one `DPoP` header. Two headers get `invalid_dpop_proof`.

Example request:

```
POST /oauth/v1/token HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=refresh_token&refresh_token=...&client_id=orders-spa
```

## Refresh tokens of a public client

- The first proof at code redemption binds the family to your key.
- Each refresh must carry a proof from that key.
- A refresh without a proof gets `invalid_dpop_proof`. A proof from another key gets `invalid_grant`.
- Neither failure uses the refresh token. A thief who has the token but not the key cannot burn it, and your client can still rotate it.
- If your app loses the key (the user clears site data), the refresh token is useless. Sign the user in again.

A confidential client already authenticates at `/token`, so Heimdall does not bind its refresh tokens (RFC 9449, section 5). Its access tokens are still bound.

## Require DPoP for your client

Ask the operator to register your client with `dpop_bound_access_tokens` (RFC 9449, section 5.2). Then `/token` refuses every request without a proof, with `invalid_dpop_proof`. An attacker cannot ask for a bearer token in your client's name.

## Errors

| Status | `error` | Cause | Action |
|---|---|---|---|
| `400` | `invalid_dpop_proof` | The proof is missing (for a client that requires DPoP, for a code bound by `dpop_jkt`, or for a bound refresh token), malformed, signed with an unsupported algorithm, for another method or URL, too old, or already used. Or the request has two `DPoP` headers. | Make a new proof with a new `jti` and the current time, then retry once. |
| `400` | `invalid_grant` | The proof is from another key than the one that the code (`dpop_jkt`) or the refresh token family is bound to. | Sign the user in again. |

Heimdall does not send a `DPoP-Nonce` yet. If your clock is wrong by more than 60 seconds, proofs fail.

## Limits today

These parts of RFC 9449 are not in Heimdall yet. They come in the next steps of issue #17.

- **`/userinfo` does not check the binding yet.** It accepts a bound access token as a bearer token (`Authorization: Bearer`). A thief who steals a bound access token can use it there until it expires. Keep access tokens short-lived and in memory.
- **Discovery does not list `dpop_signing_alg_values_supported` yet.** Configure `ES256` in your library.
- **Your own API must check the binding.** If your resource server accepts Heimdall access tokens, check that `cnf.jkt` matches the key of a valid proof in the `DPoP` header, and check `ath`. See RFC 9449, section 7.
