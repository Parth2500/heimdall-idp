// Interop with a certified library (issue #21): oidc-client-ts signs in, refreshes, revokes, and signs out against a
// running Heimdall. The library does every protocol step itself: discovery, PKCE, state, the code redemption, the ID
// token check, refresh rotation, revocation, and RP-initiated logout. This script only plays the browser.
//
// Run it against `dotnet run --launch-profile https` after `seed-dev` (see README, "Interop tests"):
//   HEIMDALL_INTEROP_EMAIL=... HEIMDALL_INTEROP_PASSWORD=... HEIMDALL_CA_FILE=.local/heimdall-dev-ca.pem pnpm run interop
// Without the variables, every test is skipped.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lookup } from 'node:dns';
import { checkServerIdentity } from 'node:tls';
import { describe, test } from 'node:test';
import { InMemoryWebStorage, OidcClient, WebStorageStateStore } from 'oidc-client-ts';
import { Agent, fetch as undiciFetch } from 'undici';

const ISSUER = process.env.HEIMDALL_ISSUER ?? 'https://acme.localhost:7200';
const EMAIL = process.env.HEIMDALL_INTEROP_EMAIL;
const PASSWORD = process.env.HEIMDALL_INTEROP_PASSWORD;
const CA_FILE = process.env.HEIMDALL_CA_FILE;
const APP = 'https://demo.localhost:4300';
const skip =
  !EMAIL || !PASSWORD || !CA_FILE
    ? 'set HEIMDALL_INTEROP_EMAIL, HEIMDALL_INTEROP_PASSWORD, HEIMDALL_CA_FILE'
    : false;

// Development TLS: the ASP.NET development certificate is issued for `localhost`. The CA is pinned and the name is
// checked against `localhost`, so certificate checks stay on. `*.localhost` resolves to loopback (RFC 6761).
if (!skip) {
  const agent = new Agent({
    connect: {
      ca: readFileSync(CA_FILE),
      checkServerIdentity: (_host, cert) =>
        checkServerIdentity(process.env.HEIMDALL_TLS_NAME ?? 'localhost', cert),
      lookup: (hostname, options, callback) =>
        lookup(hostname.endsWith('.localhost') ? 'localhost' : hostname, options, callback),
    },
  });
  globalThis.fetch = (input, init) => undiciFetch(input, { ...init, dispatcher: agent });
}

/** The browser: it keeps Heimdall's cookies and sends the antiforgery header as the account pages do. */
class Browser {
  #cookies = new Map();

  async send(url, init = {}) {
    const headers = new Headers(init.headers);
    if (this.#cookies.size > 0) {
      headers.set('cookie', [...this.#cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    }
    if (init.method && init.method !== 'GET') {
      headers.set('origin', ISSUER);
      const xsrf = this.#cookies.get('__Host-XSRF-TOKEN');
      if (xsrf) {
        headers.set('x-xsrf-token', xsrf);
      }
    }
    const response = await fetch(new URL(url, ISSUER), { ...init, headers, redirect: 'manual' });
    for (const header of response.headers.getSetCookie()) {
      const [pair] = header.split(';');
      const index = pair.indexOf('=');
      const name = pair.slice(0, index);
      const value = pair.slice(index + 1);
      if (value === '' || /expires=Thu, 01 Jan 1970/i.test(header)) {
        this.#cookies.delete(name);
      } else {
        this.#cookies.set(name, value);
      }
    }
    return response;
  }

  async signIn() {
    await this.send('/session/v1/csrf');
    const response = await this.send('/session/v1/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    assert.equal(response.status, 204, 'sign-in at Heimdall');
  }

  /** Follows one redirect and returns where it points. */
  async location(url) {
    const response = await this.send(url);
    assert.equal(response.status, 302, `redirect from ${new URL(url).pathname}`);
    return response.headers.get('location');
  }
}

function client() {
  // The demo SPA's registration from seed-dev: a public client, PKCE, and exact-match URIs.
  return new OidcClient({
    authority: ISSUER,
    client_id: 'demo-spa',
    redirect_uri: `${APP}/callback`,
    post_logout_redirect_uri: `${APP}/`,
    response_type: 'code',
    scope: 'openid email offline_access',
    loadUserInfo: false,
    stateStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
  });
}

async function signIn(oidc, browser) {
  const request = await oidc.createSigninRequest({});
  const callback = await browser.location(request.url);
  assert.ok(
    callback.startsWith(`${APP}/callback?`),
    'Heimdall returns to the registered redirect URI',
  );
  return oidc.processSigninResponse(callback);
}

// The fields of the library's RefreshState, which its package exports as a type only.
const refreshState = (response) => ({
  refresh_token: response.refresh_token,
  id_token: response.id_token,
  session_state: null,
  scope: response.scope,
  profile: response.profile,
});

describe('oidc-client-ts against Heimdall', { skip }, () => {
  test('signs in with PKCE and checks the ID token', async () => {
    const browser = new Browser();
    await browser.signIn();
    const response = await signIn(client(), browser);

    assert.equal(response.profile.iss, ISSUER);
    assert.match(response.profile.sub, /^[0-9a-f-]{36}$/);
    assert.match(response.profile.sid, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(response.token_type, 'Bearer');
    assert.equal(response.refresh_token.length, 43);
  });

  test('refreshes: the new refresh token works and the old one is reuse', async () => {
    const browser = new Browser();
    await browser.signIn();
    const oidc = client();
    const first = await signIn(oidc, browser);

    const second = await oidc.useRefreshToken({ state: refreshState(first) });
    assert.notEqual(
      second.refresh_token,
      first.refresh_token,
      'rotation gives a new refresh token',
    );
    assert.notEqual(second.access_token, first.access_token);

    // Reuse of the old token revokes the family, so the new token stops working too (no grace window).
    await assert.rejects(oidc.useRefreshToken({ state: refreshState(first) }), /invalid_grant/);
    await assert.rejects(oidc.useRefreshToken({ state: refreshState(second) }), /invalid_grant/);
  });

  test('revokes the refresh token family', async () => {
    const browser = new Browser();
    await browser.signIn();
    const oidc = client();
    const response = await signIn(oidc, browser);

    await oidc.revokeToken(response.refresh_token, 'refresh_token');

    await assert.rejects(oidc.useRefreshToken({ state: refreshState(response) }), /invalid_grant/);
  });

  test('signs out of Heimdall with the ID token, and the next sign-in asks for the password', async () => {
    const browser = new Browser();
    await browser.signIn();
    const oidc = client();
    const response = await signIn(oidc, browser);

    const request = await oidc.createSignoutRequest({
      id_token_hint: response.id_token,
      state: { from: 'interop' },
    });
    const back = await browser.location(request.url);
    assert.ok(
      back.startsWith(`${APP}/?state=`),
      'Heimdall returns to the post-logout redirect URI with state',
    );
    const signedOut = await oidc.processSignoutResponse(back);
    assert.deepEqual(signedOut.userState, { from: 'interop' });

    // The refresh tokens of that sign-in ended with the session (D33).
    await assert.rejects(oidc.useRefreshToken({ state: refreshState(response) }), /invalid_grant/);
    const next = await oidc.createSigninRequest({});
    assert.match(await browser.location(next.url), /\/account\/login\?request_id=/);
  });
});
