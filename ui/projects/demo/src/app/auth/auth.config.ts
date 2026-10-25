import { LogLevel, OpenIdConfiguration } from 'angular-auth-oidc-client';

/** The development tenant that `seed-dev` creates. Its issuer has the Kestrel port (IssuerOptions). */
export const HEIMDALL_ISSUER = 'https://acme.localhost:7200';

/** The public client that `seed-dev` registers for this application (frontend-design.md, S6). */
export const DEMO_CLIENT_ID = 'demo-spa';

/**
 * The scopes that the demo asks for. `offline_access` gets a refresh token, because the
 * client has the refresh_token grant. `email` releases `email` and `email_verified`.
 */
export const DEMO_SCOPES = 'openid email offline_access';

export function demoAuthConfig(origin: string): OpenIdConfiguration {
  return {
    authority: HEIMDALL_ISSUER,
    clientId: DEMO_CLIENT_ID,
    redirectUrl: `${origin}/callback`,
    // Exactly the URI that seed-dev registers, with the slash: Heimdall compares by exact match (D32).
    postLogoutRedirectUri: `${origin}/`,
    // Authorization code with PKCE S256. The library makes the verifier and the challenge.
    responseType: 'code',
    scope: DEMO_SCOPES,
    // Renew with the refresh token, never with a hidden iframe: Heimdall sends
    // frame-ancestors 'none', so an iframe cannot load (U10).
    useRefreshToken: true,
    silentRenew: true,
    renewTimeBeforeTokenExpiresInSeconds: 30,
    // Heimdall sends no new ID token on refresh. The library keeps the first one.
    ignoreNonceAfterRefresh: true,
    triggerRefreshWhenIdTokenExpired: false,
    // The demo calls /userinfo itself, to show the raw response.
    autoUserInfo: false,
    // A refresh token is single use. Never send one twice by accident.
    allowUnsafeReuseRefreshToken: false,
    logLevel: LogLevel.Warn,
  };
}
