# DPoP: sender-constrained tokens

DPoP (RFC 9449) binds a token to a key pair that your client holds. A thief who steals the token cannot use it without the private key. Use DPoP for a public client, such as a browser app, because a public client has no secret to protect its refresh token.

Status: Heimdall supports DPoP at `/authorize` (`dpop_jkt`), at `/token`, and at `/userinfo`. Discovery lists the proof algorithms in `dpop_signing_alg_values_supported`. The [limits](#limits-today) section lists what is not supported yet.

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

## Call `/userinfo` with a bound token

Send the bound access token with the `DPoP` scheme, and a new proof for that request:

```
GET /oauth/v1/userinfo HTTP/1.1
Host: acme.example.com
Authorization: DPoP eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCIs...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...
```

- The proof's `htm` is the request method (`GET` or `POST`), and `htu` is `<issuer>/oauth/v1/userinfo`.
- The proof has `ath`: the base64url SHA-256 hash of the access token. A proof without it, or for another token, fails.
- The proof must come from the key in the token's `cnf.jkt`, and each proof works once.
- A bound token with `Authorization: Bearer` gets `401 invalid_token`. A stolen bound token is useless without the private key.
- An unbound (bearer) token with `Authorization: DPoP` gets `401 invalid_token` too. Use the scheme that matches the `token_type` from `/token`.

A refused request gets `401` with `WWW-Authenticate: DPoP algs="ES256 RS256", error="..."`. A request with no token gets both challenges: `Bearer` and `DPoP algs="ES256 RS256"`.

## Require DPoP for your client

Ask the operator to register your client with `dpop_bound_access_tokens` (RFC 9449, section 5.2). Then `/token` refuses every request without a proof, with `invalid_dpop_proof`. An attacker cannot ask for a bearer token in your client's name.

## Errors

| Status | `error` | Cause | Action |
|---|---|---|---|
| `400` | `invalid_dpop_proof` | The proof is missing (for a client that requires DPoP, for a code bound by `dpop_jkt`, or for a bound refresh token), malformed, signed with an unsupported algorithm, for another method or URL, too old, or already used. Or the request has two `DPoP` headers. | Make a new proof with a new `jti` and the current time, then retry once. |
| `400` | `invalid_grant` | The proof is from another key than the one that the code (`dpop_jkt`) or the refresh token family is bound to. | Sign the user in again. |
| `401` | `invalid_dpop_proof` | At `/userinfo`: the proof is missing, invalid, from another key than `cnf.jkt`, without the right `ath`, or already used. | Make a new proof for this request, then retry once. |
| `401` | `invalid_token` | At `/userinfo`: a bound token with the `Bearer` scheme, or an unbound token with the `DPoP` scheme. | Use the scheme that matches `token_type`. |

Heimdall does not send a `DPoP-Nonce` yet. If your clock is wrong by more than 60 seconds, proofs fail.

## Limits today

- **No `DPoP-Nonce`.** Heimdall does not send server nonces (RFC 9449, section 8). Your clock must be within 60 seconds of Heimdall's.
- **Your own API must check the binding.** If your resource server accepts Heimdall access tokens, check that `cnf.jkt` matches the key of a valid proof in the `DPoP` header, and check `ath`. See RFC 9449, section 7, and [Validate access tokens](validate-access-tokens.md).
- **`/revoke` takes no proof.** Revocation of a bound refresh token works as for any refresh token. The family binding still stops a thief from using it.
