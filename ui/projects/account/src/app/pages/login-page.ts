import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { BridgeState, HdIcon } from 'ui-kit';
import { ActivatedRoute } from '@angular/router';
import { SessionApi, SessionApiError } from '../session/session-api';
import { BrowserNavigation, requestIdOrNull, resumePath } from '../session/flow';
import { PageFrame } from './page-frame';
import { NoSignInStatement, NoSignInText } from './no-sign-in-text';

type Field = 'email' | 'password';

interface Problem {
  readonly message: string;
  /** The field that the message is about, or null for the whole form. */
  readonly field: Field | null;
  /** True when Heimdall refused the attempt. The bridge then shows guard fire. */
  readonly refused?: boolean;
}

/**
 * The login page (U4). It signs in through the JSON API, then sends the browser to the fixed
 * resume path. It reads only `request_id` from the URL.
 */
@Component({
  selector: 'acct-login-page',
  imports: [PageFrame, NoSignInStatement, NoSignInText, HdIcon],
  template: `
    <acct-page [bridge]="bridge()">
      <div hdStatement>
        @if (requestId) {
          <h1 class="hd-display">Sign in<span class="hd-display__fire">.</span></h1>
        } @else {
          <acct-no-sign-in-statement />
        }
      </div>

      @if (requestId; as id) {
        @if (problem(); as p) {
          <div class="hd-problem" role="alert" tabindex="-1" #problemBox>
            <hd-icon class="hd-problem__icon" name="alert" />
            <p class="hd-problem__title">There is a problem</p>
            <p>
              @if (p.field) {
                <a [href]="'#' + p.field" (click)="focusField($event, p.field)">{{ p.message }}</a>
              } @else {
                {{ p.message }}
              }
            </p>
          </div>
        }

        <form class="hd-stack" novalidate (submit)="submit($event, id)">
          <div class="hd-field">
            <label class="hd-label" for="email">Email address</label>
            @if (problem()?.field === 'email') {
              <p class="hd-field-error" id="email-error">
                <span class="hd-visually-hidden">Error:</span> {{ problem()?.message }}
              </p>
            }
            <input
              class="hd-input"
              id="email"
              name="email"
              type="email"
              autocomplete="username"
              spellcheck="false"
              autocapitalize="none"
              required
              [attr.aria-invalid]="problem()?.field === 'email' ? 'true' : null"
              [attr.aria-describedby]="problem()?.field === 'email' ? 'email-error' : null"
              [value]="email()"
              (input)="email.set(value($event))"
            />
          </div>

          <div class="hd-field">
            <label class="hd-label" for="password">Password</label>
            @if (problem()?.field === 'password') {
              <p class="hd-field-error" id="password-error">
                <span class="hd-visually-hidden">Error:</span> {{ problem()?.message }}
              </p>
            }
            <div class="hd-input-row">
              <input
                class="hd-input"
                #passwordInput
                id="password"
                name="password"
                [type]="showPassword() ? 'text' : 'password'"
                autocomplete="current-password"
                required
                [attr.aria-invalid]="problem()?.field === 'password' ? 'true' : null"
                [attr.aria-describedby]="problem()?.field === 'password' ? 'password-error' : null"
                [value]="password()"
                (input)="password.set(value($event))"
              />
              <button
                type="button"
                class="hd-button hd-button--secondary"
                [attr.aria-pressed]="showPassword()"
                aria-controls="password"
                (click)="showPassword.set(!showPassword())"
              >
                {{ showPassword() ? 'Hide' : 'Show' }}
              </button>
            </div>
          </div>

          <button
            class="hd-button hd-button--block hd-button--go"
            type="submit"
            [attr.aria-disabled]="busy()"
          >
            {{ busy() ? 'Signing in' : 'Sign in' }}
            <hd-icon class="hd-button__arrow" name="arrow" />
          </button>
        </form>

        <p class="hd-small hd-muted">
          After you sign in, Heimdall sends you back to the app that asked. Heimdall never asks for
          your password on another site.
        </p>
      } @else {
        <acct-no-sign-in-text />
      }
    </acct-page>
  `,
})
export class LoginPage {
  private readonly api = inject(SessionApi);
  private readonly navigation = inject(BrowserNavigation);
  private readonly problemBox = viewChild<ElementRef<HTMLElement>>('problemBox');
  private readonly passwordInput = viewChild<ElementRef<HTMLInputElement>>('passwordInput');

  protected readonly requestId = requestIdOrNull(
    inject(ActivatedRoute).snapshot.queryParamMap.get('request_id'),
  );
  protected readonly email = signal('');
  protected readonly password = signal('');
  protected readonly showPassword = signal(false);
  protected readonly busy = signal(false);
  protected readonly problem = signal<Problem | null>(null);
  private readonly crossing = signal(false);

  /** The bridge shows the attempt: checking, refused, or crossing to the app. */
  protected readonly bridge = computed<BridgeState>(() => {
    if (this.crossing()) {
      return 'crossing';
    }
    if (this.busy()) {
      return 'busy';
    }
    return this.problem()?.refused ? 'refused' : 'idle';
  });

  protected async submit(event: Event, requestId: string): Promise<void> {
    event.preventDefault();
    if (this.busy()) {
      return;
    }

    const missing = this.missingField();
    if (missing) {
      this.show(missing);
      return;
    }

    this.busy.set(true);
    this.problem.set(null);
    try {
      await this.api.login(this.email().trim(), this.password());
      this.crossing.set(true);
      this.navigation.assign(resumePath(requestId));
    } catch (e) {
      // A failed attempt clears the password, also in the DOM: the bound value may not have
      // changed since the last render.
      this.password.set('');
      const input = this.passwordInput()?.nativeElement;
      if (input) {
        input.value = '';
      }
      this.show({ message: messageFor(e), field: null, refused: isRefusal(e) });
      this.busy.set(false);
    }
  }

  protected value(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected focusField(event: Event, field: Field): void {
    event.preventDefault();
    document.getElementById(field)?.focus();
  }

  private missingField(): Problem | null {
    if (this.email().trim() === '') {
      return { message: 'Enter your email address.', field: 'email' };
    }
    if (this.password() === '') {
      return { message: 'Enter your password.', field: 'password' };
    }
    return null;
  }

  /** Shows the problem and moves focus to it, so a screen reader reads it first (U12). */
  private show(problem: Problem): void {
    this.problem.set(problem);
    queueMicrotask(() => setTimeout(() => this.problemBox()?.nativeElement.focus()));
  }
}

/** A refusal is Heimdall's answer to the attempt: wrong credentials (401) or throttled (429). */
export function isRefusal(error: unknown): boolean {
  return error instanceof SessionApiError && (error.status === 401 || error.status === 429);
}

/** The texts of the U4 state table. The same text for an unknown account and a wrong password. */
export function messageFor(error: unknown): string {
  const e = error instanceof SessionApiError ? error : new SessionApiError(0, null, null);
  switch (e.status) {
    case 401:
      return 'The email or the password is not correct.';
    case 429:
      return e.retryAfterSeconds !== null
        ? `Too many attempts from this network. Try again in ${e.retryAfterSeconds} seconds.`
        : 'Too many attempts from this network. Try again later.';
    case 503:
      return 'Heimdall is busy. Try again in a few seconds.';
    case 0:
      return 'Heimdall did not answer. Check your connection, then try again.';
    default:
      return 'The page could not send the form. Reload the page, then try again.';
  }
}
