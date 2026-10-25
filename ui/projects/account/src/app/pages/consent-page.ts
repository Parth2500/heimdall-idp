import { Component, computed, inject, signal } from '@angular/core';
import { CardState, HdIcon } from 'ui-kit';
import { ActivatedRoute, Router } from '@angular/router';
import { ConsentPrompt, SessionApi, SessionApiError } from '../session/session-api';
import { BrowserNavigation, requestIdOrNull, resumePath } from '../session/flow';
import { NoSignInStatement, NoSignInText } from './no-sign-in-text';
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
  imports: [PageFrame, NoSignInStatement, NoSignInText, HdIcon],
  template: `
    <acct-page [state]="cardState()" hostLabel="You are signed in at">
      <div hdStatement>
        @if (!requestId) {
          <acct-no-sign-in-statement />
        } @else {
          @switch (state().kind) {
            @case ('loading') {
              <h1 class="hd-title">One moment</h1>
            }
            @case ('ended') {
              <h1 class="hd-title">This request has ended</h1>
            }
            @case ('failed') {
              <h1 class="hd-title">Heimdall did not answer</h1>
            }
            @case ('ready') {
              @if (prompt(); as p) {
                <h1 class="hd-title">Allow {{ p.client_name }} to use your account?</h1>
              }
            }
          }
        }
      </div>

      @if (!requestId) {
        <acct-no-sign-in-text />
      } @else {
        @switch (state().kind) {
          @case ('loading') {
            <p role="status">Loading the request.</p>
          }
          @case ('ended') {
            <p class="hd-lead">
              Heimdall keeps a sign-in request for 10 minutes. Go back to the app, then start again.
            </p>
          }
          @case ('failed') {
            <div class="hd-problem" role="alert">
              <hd-icon class="hd-problem__icon" name="alert" />
              <p class="hd-problem__title">There is a problem</p>
              <p>Check your connection, then try again.</p>
            </div>
            <button class="hd-button hd-button--block" type="button" (click)="load()">
              Try again
            </button>
          }
          @case ('ready') {
            @if (prompt(); as p) {
              <section aria-labelledby="asks">
                <h2 class="hd-heading" id="asks">{{ p.client_name }} asks for these scopes:</h2>
                <ul class="scopes">
                  @for (scope of p.scopes; track scope) {
                    <li>
                      <code class="scope-name">{{ scope }}</code>
                      <span>
                        @if (textFor(scope); as text) {
                          {{ text }}
                        } @else {
                          Use a permission that Heimdall does not describe.
                        }
                      </span>
                    </li>
                  }
                </ul>
              </section>

              <dl class="hd-fact">
                <dt class="hd-fact__label">After your choice, your browser goes to</dt>
                <dd class="hd-fact__value">{{ p.redirect_host }}</dd>
                <dt class="hd-visually-hidden">App ID</dt>
                <dd class="hd-fact__meta">
                  <span aria-hidden="true">App ID </span><code>{{ p.client_id }}</code>
                </dd>
              </dl>

              @if (problem()) {
                <div class="hd-problem" role="alert">
                  <hd-icon class="hd-problem__icon" name="alert" />
                  <p class="hd-problem__title">There is a problem</p>
                  <p>Heimdall did not save your choice. Try again.</p>
                </div>
              }

              <div class="hd-actions">
                <button
                  class="hd-button hd-button--secondary"
                  type="button"
                  [attr.aria-disabled]="busy()"
                  (click)="decide(false)"
                >
                  Deny
                </button>
                <button
                  class="hd-button"
                  type="button"
                  [attr.aria-disabled]="busy()"
                  (click)="decide(true)"
                >
                  Allow
                </button>
              </div>
              <p class="hd-small hd-muted">
                Heimdall asks again next time. It does not save this choice yet.
              </p>
            }
          }
        }
      }
    </acct-page>
  `,
  styles: `
    .scopes {
      list-style: none;
      margin: var(--hd-2) 0 0;
      padding: 0;
      border-top: 2px solid var(--hd-ink);
    }

    .scopes li {
      display: grid;
      grid-template-columns: 7.75rem minmax(0, 1fr);
      align-items: baseline;
      gap: var(--hd-3);
      padding-block: var(--hd-3);
      border-bottom: 1px solid var(--hd-line);
      font-size: var(--hd-text-body);
      line-height: 1.45;
    }

    .scope-name {
      color: var(--hd-link);
      font-size: 0.8125rem;
      font-weight: 600;
      word-break: break-all;
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
  private readonly decision = signal<boolean | null>(null);

  /** The card shows the decision: crossing on Allow, refused on Deny. */
  protected readonly cardState = computed<CardState>(() => {
    const decision = this.decision();
    if (decision !== null) {
      return decision ? 'crossing' : 'refused';
    }
    return this.busy() || this.state().kind === 'loading' ? 'busy' : 'idle';
  });

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
      this.decision.set(approve);
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
