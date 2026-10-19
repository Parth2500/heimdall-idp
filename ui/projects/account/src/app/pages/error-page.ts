import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { PageFrame } from './page-frame';

interface ErrorText {
  readonly title: string;
  readonly body: string;
}

/** The fixed list of U6. The page never prints a URL value that is not a key of this list. */
export const ERROR_TEXT: Readonly<Record<string, ErrorText>> = {
  invalid_request: {
    title: 'This sign-in request is not valid',
    body: 'The app sent a request that Heimdall cannot accept. Go back to the app, then try again. If it happens again, tell the owner of the app.',
  },
  invalid_client: {
    title: 'Heimdall does not know this app',
    body: 'The app is not registered here, it is not active, or it asked to return to an address that it did not register. Tell the owner of the app.',
  },
  unsupported_response_type: {
    title: 'This app asked for a sign-in that Heimdall does not support',
    body: 'Heimdall supports only the authorization code flow. Tell the owner of the app.',
  },
  temporarily_unavailable: {
    title: 'Heimdall is busy',
    body: 'Wait a moment. Then go back to the app and try again.',
  },
};

const GENERAL: ErrorText = {
  title: 'This sign-in cannot continue',
  body: 'Something went wrong with this request. Go back to the app, then try again.',
};

/** The error page (U6). `/authorize` sends a refused request here when it cannot redirect. */
@Component({
  selector: 'acct-error-page',
  imports: [PageFrame],
  template: `
    <acct-page>
      <div class="hd-stack">
        <h1 class="hd-title">{{ text.title }}</h1>
        <p class="hd-lead">{{ text.body }}</p>
        @if (code) {
          <p class="hd-small hd-muted">
            Error code: <code>{{ code }}</code>
          </p>
        }
        <p class="hd-small hd-muted">
          Heimdall did not send you back to the app, because it could not check where to send you.
        </p>
      </div>
    </acct-page>
  `,
})
export class ErrorPage {
  /** A code from the fixed list, or null. A value outside the list is never shown. */
  protected readonly code = knownCode(inject(ActivatedRoute).snapshot.queryParamMap.get('error'));
  protected readonly text = this.code ? ERROR_TEXT[this.code] : GENERAL;
}

export function knownCode(value: string | null): string | null {
  return value !== null && Object.hasOwn(ERROR_TEXT, value) ? value : null;
}
