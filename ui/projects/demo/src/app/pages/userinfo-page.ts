import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, inject, resource } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { firstValueFrom } from 'rxjs';
import { HeimdallDiscovery } from '../auth/discovery';
import { DemoSession } from '../auth/demo-session';
import { DpopKeys } from '../auth/dpop';
import { ClaimsTable } from './claims-table';

/**
 * The scope that releases each claim, from OpenID Connect Core, sections 5.4 and 5.3.2.
 * `sub` comes with every response to an `openid` request.
 */
export const RELEASING_SCOPE: Readonly<Record<string, string>> = {
  sub: 'openid',
  email: 'email',
  email_verified: 'email',
  name: 'profile',
  given_name: 'profile',
  family_name: 'profile',
  preferred_username: 'profile',
  address: 'address',
  phone_number: 'phone',
  phone_number_verified: 'phone',
};

/** The user info screen of U11. */
@Component({
  selector: 'demo-userinfo-page',
  host: { class: 'hd-stack page' },
  imports: [ClaimsTable],
  template: `
    <h1 class="hd-title">User info</h1>
    <p>
      The client sent its access token to the <code>userinfo_endpoint</code>. A DPoP-bound token
      goes with the <code>DPoP</code> scheme and a new proof from the client's key, so a copy of the
      token alone is useless. Heimdall releases a claim only when a granted scope allows it.
    </p>
    @if (userInfo.isLoading()) {
      <p role="status">Asking Heimdall.</p>
    } @else if (userInfo.error(); as error) {
      <p role="alert" class="hd-problem">{{ describe(error) }}</p>
      <button class="hd-button" type="button" (click)="userInfo.reload()">Try again</button>
    } @else if (userInfo.value(); as claims) {
      <demo-claims-table
        [claims]="claims"
        caption="Response of the userinfo endpoint"
        [notes]="scopes"
        notesHeading="Released by scope"
      />
      <button type="button" class="hd-button hd-button--secondary" (click)="userInfo.reload()">
        Ask again
      </button>
    }
  `,
})
export class UserInfoPage {
  private readonly http = inject(HttpClient);
  private readonly oidc = inject(OidcSecurityService);
  private readonly discovery = inject(HeimdallDiscovery);
  private readonly session = inject(DemoSession);
  private readonly dpop = inject(DpopKeys);
  protected readonly scopes = RELEASING_SCOPE;

  protected readonly userInfo = resource({
    params: () => this.session.tokenVersion(),
    loader: async () => {
      const { userinfo_endpoint } = await this.discovery.endpoints();
      const accessToken = await firstValueFrom(this.oidc.getAccessToken());
      const result = await firstValueFrom(this.oidc.getAuthenticationResult());
      // RFC 9449, section 7.1: a bound token needs the DPoP scheme and a proof with its hash.
      const headers: Record<string, string> =
        result?.token_type === 'DPoP'
          ? {
              Authorization: `DPoP ${accessToken}`,
              DPoP: await this.dpop.proof('GET', userinfo_endpoint, accessToken),
            }
          : { Authorization: `Bearer ${accessToken}` };
      return firstValueFrom(this.http.get<Record<string, unknown>>(userinfo_endpoint, { headers }));
    },
  });

  protected describe(error: unknown): string {
    if (error instanceof HttpErrorResponse && error.status === 0) {
      // A CORS refusal looks the same as a network error to script.
      return 'The browser got no response. Heimdall may be down, or it does not allow this origin (CORS).';
    }
    if (error instanceof HttpErrorResponse) {
      return `Heimdall answered with HTTP ${error.status}.`;
    }
    return 'The request failed.';
  }
}
