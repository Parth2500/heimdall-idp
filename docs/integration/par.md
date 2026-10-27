# Pushed authorization requests

[Documentation home](../documentation.md)

With a pushed authorization request (PAR, RFC 9126), your app sends the sign-in parameters to Heimdall directly. The browser then carries only a short reference. Nobody can read or change the scope, the redirect URI, or the PKCE challenge in the browser's address.

PAR is optional. The operator can make it required for your client (`require_pushed_authorization_requests`). Then `/authorize` refuses a request without `request_uri`.

## Step 1: Push the request

Send every parameter that you would put on `/authorize`:

```http
POST /oauth/v1/par HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded

client_id=orders-web
&response_type=code
&redirect_uri=https%3A%2F%2Forders.example.com%2Fcallback
&scope=openid%20email%20offline_access
&state=af0ifjsldkj
&nonce=n-0S6_WzA2Mj
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
```

- A confidential client sends HTTP Basic, and no `client_id` in the body.
- A public client sends `client_id` in the body.
- Do not send `request_uri` in the body.

Heimdall answers:

```http
HTTP/1.1 201 Created
Cache-Control: no-store
Content-Type: application/json

{"request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c", "expires_in": 60}
```

Heimdall runs the checks of `/authorize` here. A refused request gets a JSON error, as at `/token`, for example `{"error": "invalid_scope"}`. Heimdall never redirects from `/par`.

## Step 2: Send the browser to `/authorize`

```http
GET /oauth/v1/authorize?client_id=orders-web&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A6esc_11ACC5bwc014ltc14eY22c HTTP/1.1
Host: acme.example.com
```

- Use the `request_uri` within 60 seconds, and once. A second use gets Heimdall's error page.
- Send the same `client_id` that pushed the request.
- Heimdall ignores every other parameter in this address. It uses only the pushed values.

The rest of the flow does not change: the sign-in page, the code in the redirect with `state` and `iss`, and the code redemption at `/token`. See [Sign in users](sign-in-users.md).

## DPoP

Send a DPoP proof with the push to bind the code to your key (RFC 9449, section 10.1). The proof's `htu` is the PAR endpoint URL, and `htm` is `POST`. Only a proof from the same key then redeems the code at `/token`. If you also send `dpop_jkt`, it must name the same key. Otherwise Heimdall answers `invalid_dpop_proof`. See [DPoP](dpop.md).

## Library support

- For a browser library, check its documentation for PAR support. Without it, push the request with your own `fetch` call, then send the browser to `/authorize` yourself.
- ASP.NET Core 9 and later: `PushedAuthorizationBehavior` on `OpenIdConnectOptions` uses PAR when discovery lists the endpoint.
- `openid-client` (Node.js): `buildAuthorizationUrlWithPAR(config, parameters)`.
