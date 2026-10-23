import { Component, computed, inject, signal } from '@angular/core';
import { BridgeState, HdIcon, IconName } from 'ui-kit';
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

/** An icon for each known scope. An unknown scope gets the key. */
const SCOPE_ICON: Readonly<Record<string, IconName>> = {
  openid: 'id',
  profile: 'person',
  email: 'mail',
  address: 'home',
  phone: 'phone',
  offline_access: 'offline',
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
    <acct-page [bridge]="bridge()" plateLabel="You are signed in at">
      <div hdStatement>
        @if (!requestId) {
          <acct-no-sign-in-statement />
        } @else {
          @switch (state().kind) {
            @case ('loading') {
              <p class="hd-display" aria-hidden="true">
                One moment<span class="hd-display__fire">.</span>
              </p>
            }
            @case ('ended') {
              <p class="hd-display" aria-hidden="true">
                Too late<span class="hd-display__fire">.</span>
              </p>
              <h1 class="hd-subline">This request has ended</h1>
            }
            @case ('failed') {
              <p class="hd-display" aria-hidden="true">
                No answer<span class="hd-display__fire">.</span>
              </p>
              <h1 class="hd-subline">Heimdall did not answer</h1>
            }
            @case ('ready') {
              @if (prompt(); as p) {
                <p
                  class="hd-display"
                  [class]="'name-' + nameLength(p.client_name)"
                  aria-hidden="true"
                >
                  Let {{ p.client_name }} in<span class="hd-display__fire">?</span>
                </p>
                <h1 class="hd-subline">Allow {{ p.client_name }} to use your account?</h1>
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
                <h2 class="hd-heading" id="asks">{{ p.client_name }} asks to</h2>
                <ul class="hd-rule-list scopes">
                  @for (scope of p.scopes; track scope) {
                    <li>
                      <hd-icon [name]="iconFor(scope)" />
                      <span>
                        @if (textFor(scope); as text) {
                          {{ text }}
                        } @else {
                          Use the permission <code>{{ scope }}</code
                          >.
                        }
                      </span>
                      <code class="scope-name" aria-hidden="true">{{ scope }}</code>
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
                  class="hd-button hd-button--go"
                  type="button"
                  [attr.aria-disabled]="busy()"
                  (click)="decide(true)"
                >
                  Allow
                  <hd-icon class="hd-button__arrow" name="arrow" />
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
            }
          }
        }
      }
    </acct-page>
  `,
  styles: `
    .scopes li {
      display: grid;
      grid-template-columns: auto 1fr auto;
      align-items: start;
      gap: var(--hd-3);
      padding-block: var(--hd-3);
    }

    .scopes hd-icon {
      color: var(--hd-act);
      margin-top: 0.0625rem;
    }

    .scope-name {
      color: var(--hd-ink-muted);
      font-size: var(--hd-text-xs);
      padding-top: 0.2rem;
    }

    /* A long app name steps the display down, so it never breaks the gate. */
    /* An app name is one unit: the statement may run wider than other pages, never break it. */
    .name-s,
    .name-m,
    .name-l {
      --hd-display-measure: 7em;
      overflow-wrap: normal;
    }

    .name-m {
      --hd-display-size: clamp(3rem, 1rem + 6.5vw, 7.5rem);
    }

    .name-l {
      --hd-display-size: clamp(2.5rem, 1rem + 4.5vw, 5.25rem);
    }

    /* Phone: Allow and Deny stay in the first screen, so the statement and the rows are tighter. */
    @media (max-width: 39.99rem) {
      .scopes li {
        padding-block: var(--hd-2);
      }

      .name-s,
      .name-m,
      .name-l {
        --hd-display-size: 2.75rem;
      }
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

  /** The bridge shows the decision: light on Allow, guard fire on Deny. */
  protected readonly bridge = computed<BridgeState>(() => {
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

  protected iconFor(scope: string): IconName {
    return Object.hasOwn(SCOPE_ICON, scope) ? SCOPE_ICON[scope] : 'key';
  }

  /** The size step of the display for an app name: short, medium, or long. */
  protected nameLength(name: string): 's' | 'm' | 'l' {
    return name.length <= 8 ? 's' : name.length <= 16 ? 'm' : 'l';
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
