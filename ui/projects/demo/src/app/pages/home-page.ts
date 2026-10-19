import { Component, DestroyRef, computed, inject, resource, signal } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { firstValueFrom } from 'rxjs';
import { HEIMDALL_ISSUER } from '../auth/auth.config';
import { DemoSession } from '../auth/demo-session';
import { ClaimsTable } from './claims-table';

/** The signed-out screen and the signed-in screen of U11. */
@Component({
  selector: 'demo-home-page',
  host: { class: 'hd-stack page' },
  imports: [ClaimsTable],
  template: `
    @if (session.state() === 'signed-in') {
      <h1 class="hd-title">Signed in</h1>

      <section aria-labelledby="expiry-heading">
        <h2 class="hd-heading" id="expiry-heading">Access token</h2>
        @if (secondsLeft() !== null) {
          <p>
            It expires in <strong>{{ secondsLeft() }} s</strong>. The library refreshes it 30
            seconds before that.
          </p>
        } @else {
          <p>The access token has no expiry claim that the demo can read.</p>
        }
      </section>

      <section aria-labelledby="claims-heading">
        <h2 class="hd-heading" id="claims-heading">ID token claims</h2>
        <p>The library verified the signature with a key from the Heimdall JWKS.</p>
        @if (idClaims.value(); as claims) {
          <demo-claims-table [claims]="claims" caption="Decoded ID token payload" />
        }
      </section>
    } @else {
      <h1 class="hd-title">Sign in with Heimdall</h1>
      <p>
        This client is a public client. It uses the authorization code flow with PKCE (S256) against
        <code>{{ issuer }}</code
        >. It keeps its tokens in memory only.
      </p>
      @if (session.error(); as error) {
        <p role="alert" class="hd-problem">
          Heimdall did not sign you in. The error code is <code>{{ error }}</code
          >.
        </p>
      }
      @if (session.unreachable()) {
        <div role="alert" class="hd-problem">
          <p class="hd-problem__title">The demo cannot reach Heimdall</p>
          <p>
            Heimdall may not be running, or your browser has not accepted its development
            certificate. Open
            <a [href]="discoveryUrl" target="_blank" rel="noopener"
              >Heimdall's discovery document</a
            >
            in a new tab, accept the certificate, then try again.
          </p>
        </div>
      }
      @if (session.signedOutHere()) {
        <p role="status" class="hd-note">
          The client revoked its refresh token and dropped its tokens. Your Heimdall session is
          still active, so the next sign-in may not ask for a password. Heimdall has no RP-initiated
          logout yet.
        </p>
      }
      <button class="hd-button" type="button" (click)="session.signIn()">
        Sign in with Heimdall
      </button>
    }
  `,
})
export class HomePage {
  protected readonly session = inject(DemoSession);
  private readonly oidc = inject(OidcSecurityService);
  protected readonly issuer = HEIMDALL_ISSUER;
  protected readonly discoveryUrl = `${HEIMDALL_ISSUER}/.well-known/openid-configuration`;

  protected readonly idClaims = resource({
    params: () => (this.session.state() === 'signed-in' ? this.session.tokenVersion() : undefined),
    loader: () =>
      firstValueFrom(this.oidc.getPayloadFromIdToken()) as Promise<Record<string, unknown>>,
  });

  private readonly accessClaims = resource({
    params: () => (this.session.state() === 'signed-in' ? this.session.tokenVersion() : undefined),
    loader: () =>
      firstValueFrom(this.oidc.getPayloadFromAccessToken()) as Promise<Record<string, unknown>>,
  });

  private readonly now = signal(Date.now());

  /** Seconds until the access token's `exp`, or null when the token has no number there. */
  protected readonly secondsLeft = computed(() => {
    const exp = this.accessClaims.value()?.['exp'];
    return typeof exp === 'number' ? Math.max(0, Math.floor(exp - this.now() / 1000)) : null;
  });

  constructor() {
    const timer = setInterval(() => this.now.set(Date.now()), 1000);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }
}
