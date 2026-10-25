import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NoSignInStatement, NoSignInText } from './no-sign-in-text';
import { PageFrame } from './page-frame';

/**
 * The signed-out page (U2). After a sign-out, Heimdall adds `logout=done`, and the page confirms it.
 * Without the marker, the page says only what is true: no sign-in is in progress. The marker is a
 * fixed value, so the URL can change no text on the page.
 */
@Component({
  selector: 'acct-signed-out-page',
  imports: [PageFrame, NoSignInStatement, NoSignInText],
  template: `
    <acct-page>
      <div hdStatement>
        @if (signedOut) {
          <h1 class="hd-title">You are signed out</h1>
          <p class="hd-subtitle">Heimdall ended your session on this browser.</p>
        } @else {
          <acct-no-sign-in-statement />
        }
      </div>

      @if (signedOut) {
        <p class="hd-lead">
          The next sign-in asks for your password. You can close this tab, or go back to an app and
          sign in again.
        </p>
      } @else {
        <acct-no-sign-in-text />
      }
    </acct-page>
  `,
})
export class SignedOutPage {
  protected readonly signedOut =
    inject(ActivatedRoute).snapshot.queryParamMap.get('logout') === 'done';
}
