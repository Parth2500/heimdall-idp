# Recipe: Node.js server

[Documentation home](../../documentation.md)

This recipe connects a Node.js server app to Heimdall as a confidential client. It uses [`openid-client`](https://github.com/panva/openid-client) version 6, a certified OpenID Connect library. The Huginn chat app (NestJS) uses this setup and signs in end to end.

The server app does the whole flow. The browser never sees a Heimdall token. This is the backend-for-frontend (BFF) pattern, and it is the safest choice for a web app.

## Registration

| Setting | Value |
|---|---|
| Client type | Confidential |
| Grants | `authorization_code` (add `refresh_token` only if the server calls an API for the user later) |
| Redirect URI | `https://app.example.com/auth/callback` |
| Scopes | `openid email` |

Keep the client secret in an environment variable or a secret store.

## Install

```sh
npm install openid-client
```

## Discovery

```ts
import * as oidc from 'openid-client';

const settings = {
  issuer: process.env.HEIMDALL_ISSUER!,          // https://acme.example.com
  clientId: process.env.HEIMDALL_CLIENT_ID!,
  clientSecret: process.env.HEIMDALL_CLIENT_SECRET!,
  redirectUri: process.env.HEIMDALL_REDIRECT_URI!,
};

let config: Promise<oidc.Configuration> | null = null;

/** Discovery, cached after it succeeds. A failure is tried again on the next sign-in. */
function configuration(): Promise<oidc.Configuration> {
  config ??= oidc
    .discovery(
      new URL(settings.issuer),
      settings.clientId,
      undefined,
      // Heimdall supports client_secret_basic only. The library default is different.
      oidc.ClientSecretBasic(settings.clientSecret),
    )
    .catch((error: unknown) => {
      config = null;
      throw error;
    });
  return config;
}
```

`oidc.ClientSecretBasic` is required. Without it, the library can send the secret in the body, and Heimdall refuses that with `invalid_request`.

## Start the sign-in

```ts
interface Transaction {
  verifier: string;
  state: string;
  nonce: string;
}

export async function startSignIn(): Promise<{ url: string; transaction: Transaction }> {
  const transaction: Transaction = {
    verifier: oidc.randomPKCECodeVerifier(),
    state: oidc.randomState(),
    nonce: oidc.randomNonce(),
  };
  const url = oidc.buildAuthorizationUrl(await configuration(), {
    redirect_uri: settings.redirectUri,
    scope: 'openid email',
    code_challenge: await oidc.calculatePKCECodeChallenge(transaction.verifier),
    code_challenge_method: 'S256',
    state: transaction.state,
    nonce: transaction.nonce,
  });
  return { url: url.href, transaction };
}
```

Store the transaction where the callback can read it, and only for this browser. Use one of these options:

- Your server-side session.
- A short-lived cookie that is encrypted and signed, with `HttpOnly`, `Secure`, and `SameSite=Lax`. `Lax` is required, because the callback is a cross-site navigation from Heimdall.

Then redirect the browser to `url`.

## Handle the callback

```ts
export async function completeSignIn(callbackUrl: URL, pending: Transaction) {
  const config = await configuration();

  // Checks state, iss (RFC 9207), the code redemption with PKCE, the ID token signature and claims, and nonce.
  const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
    pkceCodeVerifier: pending.verifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });

  const claims = tokens.claims()!;

  // The ID token has no email. Read it from /userinfo with the access token.
  const info = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);

  return {
    issuer: claims.iss,
    subject: claims.sub,
    email: typeof info.email === 'string' ? info.email : null,
  };
}
```

`callbackUrl` is the full URL of the callback request, with its query string. Delete the stored transaction after this call, whether it succeeds or fails.

Then create your app's own session, keyed by (`issuer`, `subject`). Do not keep the Heimdall tokens if you do not need them.

## Express example

```ts
import express from 'express';

const app = express();

app.get('/auth/login', async (req, res) => {
  const { url, transaction } = await startSignIn();
  req.session.heimdall = transaction; // your session middleware
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const pending = req.session.heimdall;
  delete req.session.heimdall;
  if (!pending) {
    return res.status(400).send('The sign-in expired. Try again.');
  }
  const callbackUrl = new URL(req.originalUrl, settings.redirectUri);
  try {
    const user = await completeSignIn(callbackUrl, pending);
    req.session.regenerate(() => {
      req.session.user = user;
      res.redirect('/');
    });
  } catch {
    res.status(400).send('The sign-in failed. Try again.');
  }
});
```

Regenerate the session ID after sign-in. This stops session fixation.

## Development with a local Heimdall

The development tenant `https://acme.localhost:7200` uses the ASP.NET Core development certificate, which is issued for `localhost`. Node.js does not trust it by default. Do not turn off certificate checks. Huginn pins the certificate instead, with a custom `fetch` (see `HEIMDALL_CA_FILE` in `../demo-chat-app/api/src/auth/heimdall-oidc.provider.ts`).

A redirect URI on `http://localhost` is allowed for development, because it is a loopback address. Production redirect URIs must use `https`.

## Sign out

Delete your app's session. If you kept a refresh token, revoke it first with `oidc.tokenRevocation(config, refreshToken)`. See [Sign out](../sign-out.md).
