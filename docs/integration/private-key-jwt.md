# Authenticate with a private key

[Documentation home](../documentation.md)

A confidential client can authenticate with `private_key_jwt` (RFC 7523) instead of a client secret. Your server keeps the private key. Heimdall stores only your public key, so no shared secret can leak from Heimdall, a log, or a proxy.

Use it at every endpoint that authenticates a client: `/oauth/v1/token`, `/oauth/v1/revoke`, `/oauth/v1/introspect`, and `/oauth/v1/par`.

## Register your keys

1. Make a key pair. Heimdall accepts EC P-256 (`ES256`) and RSA with 2048 to 4096 bits (`RS256`, `PS256`).
2. Give the operator your public keys as a JWK Set. Each key needs a unique `kid`.
   ```json
   {
     "keys": [
       { "kty": "EC", "crv": "P-256", "kid": "2026-10", "x": "...", "y": "..." }
     ]
   }
   ```
3. Do not send the private key. Heimdall refuses a key set that holds a private member (`d`, `p`, `q`, and the others).

A client has one method. After the change to `private_key_jwt`, your old client secret stops working.

To rotate a key, give the operator a new set with the old key and the new key. Start to sign with the new key. Then give the operator a set with the new key only. A set has at most 5 keys.

Heimdall does not fetch keys from a `jwks_uri`. The operator registers the keys.

## Make an assertion

Make a new JWT for each request and sign it with your private key.

| Part | Value |
|---|---|
| Header `alg` | `ES256`, `RS256`, or `PS256`. It must match the key type. |
| Header `kid` | The `kid` of the key that signs. |
| Header `typ` | Recommended: `client-authentication+jwt`. `JWT` also works. |
| `iss` | Your `client_id`. |
| `sub` | Your `client_id`. |
| `aud` | The issuer of your tenant, for example `https://acme.example.com`. One string, exactly. Not the token endpoint URL. |
| `jti` | A new random value for each assertion. Heimdall refuses a value that it has seen. |
| `exp` | At most 5 minutes from now. |
| `iat` | Recommended. Not in the future. |

Heimdall allows a clock difference of 60 seconds.

Some libraries put the token endpoint URL in `aud` by default. Set them to use the issuer. Heimdall refuses an endpoint URL, so an assertion that you made for another server, or for one endpoint, cannot be used here (the 2025 audience injection attack).

## Send the assertion

```http
POST /oauth/v1/token HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=orders.read
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMTAiLCJ0eXAiOiJjbGllbnQtYXV0aGVudGljYXRpb24rand0In0...
```

- Do not send an `Authorization: Basic` header with the assertion. Two methods in one request get `invalid_request`.
- `client_id` in the body is optional. If you send it, it must equal `iss` and `sub`.

## Errors

Every failure of the assertion is `invalid_client` with status 401. Heimdall does not say which check failed. The usual causes are:

- `aud` is the token endpoint URL, not the issuer.
- The assertion was already used. Make a new `jti` for each request, also for a retry.
- `exp` is more than 5 minutes away, or the server clock is wrong.
- `kid` does not name a registered key.
