# Validate access tokens

[Documentation home](../documentation.md)

This page is for resource servers: APIs that accept Heimdall access tokens. A resource server checks each token itself, with the public keys from the JWKS. It does not call Heimdall for each request.

## The access token

An access token is a JWT (RFC 9068). Example header and payload:

```json
{
  "alg": "RS256",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "typ": "at+jwt"
}
```

```json
{
  "iss": "https://acme.example.com",
  "sub": "0199f0a2-7c1e-7b3a-9d2f-5e8a1c4b6d70",
  "aud": "https://api.orders.example.com",
  "client_id": "orders-web",
  "iat": 1761120000,
  "exp": 1761120300,
  "jti": "8f14e45fceea167a5a36dedd4bea2543",
  "scope": "openid orders.read",
  "auth_time": 1761119950
}
```

| Claim | Meaning |
|---|---|
| `iss` | The tenant's issuer. |
| `sub` | The user. In a service token, the `client_id` of the service. |
| `aud` | The one resource server that may accept this token. It is a string, not an array. |
| `client_id` | The client that asked for the token. |
| `iat`, `exp` | Issue time and expiry, in seconds since the epoch. |
| `jti` | A unique ID for the token. |
| `scope` | The granted scopes, separated by spaces. Absent if no scope was granted. |
| `auth_time` | When the user signed in. Only in user tokens. |
| `cnf` | Only in a DPoP-bound token: `{"jkt": "<key thumbprint>"}` (RFC 9449, section 6.1). |

## Required checks

Do every check. Refuse the token if one check fails.

| # | Check | Rule |
|---|---|---|
| 1 | Format | A compact JWS with three parts. |
| 2 | `typ` | `at+jwt`. This check stops an ID token from being used as an access token. |
| 3 | `alg` | `RS256` only. Do not read the allowed algorithm from the token. Refuse `none` and every `HS*` algorithm. |
| 4 | Signature | Use the key from the JWKS whose `kid` matches the header. |
| 5 | `iss` | Equals the tenant's issuer exactly. |
| 6 | `aud` | Equals your API's audience exactly. A token for another API must fail here. |
| 7 | `exp` | Is in the future. Allow at most 5 minutes of clock skew. |
| 8 | `scope` | Contains the scope that the operation needs. |
| 9 | `cnf` | If the token has `cnf`, it is DPoP-bound. Accept it only with `Authorization: DPoP` and a valid proof whose key thumbprint equals `cnf.jkt`, whose `ath` is the token's hash, and whose `jti` you have not seen. Refuse a bound token with `Authorization: Bearer`. See RFC 9449, section 7. |

Check 6 matters most for security. Check 9 matters as much for a bound token: without it, a stolen bound token works as a bearer token. Without it, any client that has a token for any API in the tenant could call your API.

Use a JWT library. Do not write signature checks by hand.

## Get and cache the keys

Read `jwks_uri` from discovery, then fetch the JWKS. Do not fetch it for each request.

- Cache the JWKS for the `max-age` that Heimdall sends (10 minutes by default). Send the `ETag` back in `If-None-Match`. An unchanged set returns `304` with no body.
- If a token has a `kid` that is not in your cache, fetch the JWKS once more. Limit this refetch, for example to once each minute, so bad tokens cannot make you flood Heimdall.

Heimdall rotates signing keys. A new key appears in the JWKS at least 11 minutes before Heimdall signs with it. An old key stays in the JWKS until every token that it signed has expired. A resource server that follows the `max-age` always has the right key.

## Errors to return

Follow RFC 6750, section 3:

| Case | Status | Header |
|---|---|---|
| No token | `401` | `WWW-Authenticate: Bearer` |
| Bad, expired, or wrong-audience token | `401` | `WWW-Authenticate: Bearer error="invalid_token"` |
| Valid token, missing scope | `403` | `WWW-Authenticate: Bearer error="insufficient_scope"` |

Accept the token in the `Authorization: Bearer` header only. Do not accept it in a query string. URLs end up in logs.

## User tokens and service tokens

A user token has `auth_time`, and `sub` is the user. A service token from `client_credentials` has no `auth_time`, and `sub` is the `client_id` of the service.

If an operation must run for a user, refuse tokens that have no `auth_time`.

## Revocation and logout

With the checks above, an access token is valid until `exp`. A sign-out, a reuse, or `/revoke` ends the token's family at Heimdall, but a JWT that you check offline does not show it. The short lifetime (5 minutes by default) limits the risk.

If an operation must see a revocation at once, ask Heimdall with introspection (RFC 7662). Use it only for those operations. Every call costs a round trip.

1. Register your resource server as a confidential client. The operator adds your audience, for example `https://api.orders.example.com`, to its `resource_audiences`.
2. Call the endpoint with your client secret:

```http
POST /oauth/v1/introspect HTTP/1.1
Host: acme.example.com
Authorization: Basic b3JkZXJzLWFwaTpzM2NyZXQ=
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUzI1NiIs...
```

An active token:

```json
{
  "active": true,
  "scope": "openid orders.read",
  "client_id": "orders-web",
  "sub": "0190f1e2-3a4b-7c5d-8e9f-a0b1c2d3e4f5",
  "aud": "https://api.orders.example.com",
  "iss": "https://acme.example.com",
  "exp": 1792603778,
  "iat": 1792603478,
  "token_type": "Bearer"
}
```

A DPoP-bound token has `"token_type": "DPoP"` and `"cnf": {"jkt": "..."}`. Check the proof as usual.

Every other token gets `{"active": false}`: invalid, expired, revoked, from a signed-out session, unknown, or a token that you may not see. You may see an access token when its `aud` is one of your `resource_audiences`, or when it was issued to your own client. Do not cache an answer: the response has `Cache-Control: no-store`, and a sign-out can come at any second.

A public client cannot call introspection. It gets `401` with `invalid_client`.

## Examples

### Node.js with `jose`

```ts
import { createRemoteJWKSet, jwtVerify } from 'jose';

const issuer = 'https://acme.example.com';
const audience = 'https://api.orders.example.com';

// jose caches the keys and refetches on an unknown kid, with a cooldown.
const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));

export async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience,
    algorithms: ['RS256'],
    typ: 'at+jwt',
    clockTolerance: '5 minutes',
  });
  return payload;
}

export function hasScope(payload: { scope?: unknown }, needed: string) {
  return typeof payload.scope === 'string' && payload.scope.split(' ').includes(needed);
}
```

Take the JWKS URL from discovery in production. The fixed path here keeps the example short.

### ASP.NET Core with `JwtBearer`

```csharp
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Discovery and the JWKS come from the authority.
        options.Authority = "https://acme.example.com";
        options.Audience = "https://api.orders.example.com";
        options.MapInboundClaims = false;
        options.TokenValidationParameters.ValidIssuer = "https://acme.example.com";
        options.TokenValidationParameters.ValidTypes = ["at+jwt"];
        options.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];
        options.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(5);
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("orders.read", policy => policy.RequireAssertion(context =>
        context.User.FindFirst("scope")?.Value.Split(' ').Contains("orders.read") == true));
```

Set `ValidTypes`. Without it, the handler does not check `typ` (check 2). `MapInboundClaims = false` keeps the claim names as Heimdall writes them, so `scope` stays `scope`. This example is not yet tested against Heimdall.
