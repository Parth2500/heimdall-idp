import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ConsentPrompt, SessionApi, SessionApiError } from '../session/session-api';
import { BrowserNavigation, requestIdOrNull, resumePath } from '../session/flow';
import { NoSignInText } from './no-sign-in-text';
import { PageFrame } from './page-frame';

/**
 * Fixed text for each known scope. Heimdall controls this text; it never comes from the client
 * registration (U5). An unknown scope shows as its raw name in code style.
 */
export const SCOPE_TEXT: Readonly<Record<string, string>> = {
  openid: 'Know that it is you, through an account ID that stays the same.',
  profile: 'Read your basic profile.',
  email: 'Read your email address.',
  address: 'Read your postal address.',
  phone: 'Read your phone number.',
  offline_access: 'Stay connected after you close the app, until you sign out of it.',
};

type State =
  | { kind: 'loading' }
  | { kind: 'ready'; prompt: ConsentPrompt }
  | { kind: 'ended' }
  | { kind: 'failed' };

/** The consent page (U5). It shows only server values and sends only the decision. */
@Component({
  selector: 'acct-consent-page',
  imports: [PageFrame, NoSignInText],
  template: `
    <acct-page [busy]="busy() || state().kind === 'loading'">
      @if (!requestId) {
        <acct-no-sign-in-text />
      } @else {
        @switch (state().kind) {
          @case ('loading') {
            <p role="status">Loading the request.</p>
          }
          @case ('ended') {
            <div class="hd-stack">
              <h1 class="hd-title">This request has ended</h1>
              <p class="hd-lead">
                Heimdall keeps a sign-in request for 10 minutes. Go back to the app, then start
                again.
              </p>
            </div>
          }
          @case ('failed') {
            <div class="hd-stack">
              <h1 class="hd-title">Heimdall did not answer</h1>
              <div class="hd-problem" role="alert">
                <p class="hd-problem__title">There is a problem</p>
                <p>Check your connection, then try again.</p>
              </div>
              <button class="hd-button" type="button" (click)="load()">Try again</button>
            </div>
          }
          @case ('ready') {
            @if (prompt(); as p) {
              <div class="hd-stack">
                <h1 class="hd-title">Allow {{ p.client_name }} to use your account?</h1>

                <div class="hd-stack-tight">
                  <h2 class="hd-heading">{{ p.client_name }} asks to</h2>
                  <ul class="hd-rule-list">
                    @for (scope of p.scopes; track scope) {
                      <li>
                        @if (textFor(scope); as text) {
                          {{ text }}
                        } @else {
                          Use the permission <code>{{ scope }}</code
                          >.
                        }
                      </li>
                    }
                  </ul>
                </div>

                <dl class="facts">
                  <div>
                    <dt class="hd-muted hd-small">After your choice, your browser goes to</dt>
                    <dd class="hd-code">{{ p.redirect_host }}</dd>
                  </div>
                  <div>
                    <dt class="hd-muted hd-small">App ID</dt>
                    <dd class="hd-code">{{ p.client_id }}</dd>
                  </div>
                </dl>

                @if (problem()) {
                  <div class="hd-problem" role="alert">
                    <p class="hd-problem__title">There is a problem</p>
                    <p>Heimdall did not save your choice. Try again.</p>
                  </div>
                }

                <div class="hd-actions">
                  <button
                    class="hd-button"
                    type="button"
                    [attr.aria-disabled]="busy()"
                    (click)="decide(true)"
                  >
                    Allow
                  </button>
                  <button
                    class="hd-button hd-button--secondary"
                    type="button"
                    [attr.aria-disabled]="busy()"
                    (click)="decide(false)"
                  >
                    Deny
                  </button>
                </div>
                <p class="hd-small hd-muted">
                  Heimdall asks again next time. It does not save this choice yet.
                </p>
              </div>
            }
          }
        }
      }
    </acct-page>
  `,
  styles: `
    .facts {
      display: grid;
      gap: var(--hd-4);
    }

    .facts dd {
      font-size: var(--hd-text-m);
      font-weight: 700;
    }
  `,
})
export class ConsentPage {
  private readonly api = inject(SessionApi);
  private readonly navigation = inject(BrowserNavigation);
  private readonly router = inject(Router);

  protected readonly requestId = requestIdOrNull(
    inject(ActivatedRoute).snapshot.queryParamMap.get('request_id'),
  );
  protected readonly state = signal<State>({ kind: 'loading' });
  protected readonly busy = signal(false);
  protected readonly problem = signal(false);

  constructor() {
    void this.load();
  }

  protected prompt(): ConsentPrompt | null {
    const s = this.state();
    return s.kind === 'ready' ? s.prompt : null;
  }

  protected textFor(scope: string): string | null {
    return Object.hasOwn(SCOPE_TEXT, scope) ? SCOPE_TEXT[scope] : null;
  }

  protected async load(): Promise<void> {
    if (!this.requestId) {
      return;
    }
    this.state.set({ kind: 'loading' });
    try {
      this.state.set({ kind: 'ready', prompt: await this.api.consentPrompt(this.requestId) });
    } catch (e) {
      await this.handle(e);
    }
  }

  protected async decide(approve: boolean): Promise<void> {
    if (!this.requestId || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(false);
    try {
      await this.api.decide(this.requestId, approve);
      this.navigation.assign(resumePath(this.requestId));
    } catch (e) {
      this.busy.set(false);
      if (e instanceof SessionApiError && (e.status === 401 || e.status === 400)) {
        await this.handle(e);
      } else {
        this.problem.set(true);
      }
    }
  }

  private async handle(error: unknown): Promise<void> {
    const status = error instanceof SessionApiError ? error.status : 0;
    if (status === 401) {
      // The session ended. Sign in again for the same stored request (U5).
      await this.router.navigate(['/login'], { queryParams: { request_id: this.requestId } });
      return;
    }
    this.state.set(status === 400 || status === 404 ? { kind: 'ended' } : { kind: 'failed' });
  }
}
