import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, inject, resource } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { firstValueFrom } from 'rxjs';
import { HeimdallDiscovery } from '../auth/discovery';
import { DemoSession } from '../auth/demo-session';
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
  imports: [ClaimsTable],
  template: `
    <h1>User info</h1>
    <p>
      The client sent its access token to the <code>userinfo_endpoint</code> as a bearer token.
      Heimdall releases a claim only when a granted scope allows it.
    </p>
    @if (userInfo.isLoading()) {
      <p role="status">Asking Heimdall.</p>
    } @else if (userInfo.error(); as error) {
      <p role="alert" class="notice">{{ describe(error) }}</p>
      <button type="button" (click)="userInfo.reload()">Try again</button>
    } @else if (userInfo.value(); as claims) {
      <demo-claims-table
        [claims]="claims"
        caption="Response of the userinfo endpoint"
        [notes]="scopes"
        notesHeading="Released by scope"
      />
      <button type="button" class="quiet" (click)="userInfo.reload()">Ask again</button>
    }
  `,
})
export class UserInfoPage {
  private readonly http = inject(HttpClient);
  private readonly oidc = inject(OidcSecurityService);
  private readonly discovery = inject(HeimdallDiscovery);
  private readonly session = inject(DemoSession);
  protected readonly scopes = RELEASING_SCOPE;

  protected readonly userInfo = resource({
    params: () => this.session.tokenVersion(),
    loader: async () => {
      const { userinfo_endpoint } = await this.discovery.endpoints();
      const accessToken = await firstValueFrom(this.oidc.getAccessToken());
      return firstValueFrom(
        this.http.get<Record<string, unknown>>(userinfo_endpoint, {
          headers: { Authorization: `Bearer ${accessToken}` },
        }),
      );
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
