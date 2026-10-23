import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { DemoSession } from '../auth/demo-session';
import { RefreshTokenHistory } from '../auth/refresh-token-history';
import { StealDemoResult, TheftDemo, TheftDemoResult } from '../theft/theft-demo';
import { DpopKeys } from '../auth/dpop';

/** The refresh screen and the theft demo screen of U11. */
@Component({
  selector: 'demo-tokens-page',
  host: { class: 'hd-stack page' },
  imports: [DatePipe],
  template: `
    <h1 class="hd-title">Refresh and theft</h1>

    @if (session.state() === 'signed-in') {
      <section aria-labelledby="refresh-heading">
        <h2 class="hd-heading" id="refresh-heading">Refresh token rotation</h2>
        <p>
          Each refresh gives the client a new refresh token. Heimdall marks the old one as used. The
          page shows the first 6 hex characters of the SHA-256 of each token, never the token.
        </p>
        <ol class="rotations">
          @for (rotation of history.rotations(); track rotation.fingerprint; let last = $last) {
            <li>
              <code>{{ rotation.fingerprint }}</code>
              <span>received {{ rotation.receivedAt | date: 'HH:mm:ss' }}</span>
              <span>{{ last ? 'current' : 'used' }}</span>
            </li>
          }
        </ol>
        <button class="hd-button" type="button" (click)="refresh()" [disabled]="busy()">
          Refresh now
        </button>
        @if (refreshError()) {
          <p role="alert" class="hd-problem">
            The refresh failed. Sign in again to get a new token family.
          </p>
        }
      </section>
    }

    <section aria-labelledby="theft-heading">
      <h2 class="hd-heading" id="theft-heading">Theft demo</h2>
      <p>
        An attacker who copied the previous refresh token now sends it to the token endpoint. Then
        the demo sends the current token, as the real client would.
      </p>
      @if (session.state() === 'signed-in') {
        @if (!history.hasPrevious()) {
          <p>Refresh once first, so that a used token exists.</p>
        }
        <button
          class="hd-button"
          type="button"
          (click)="replay()"
          [disabled]="busy() || !history.hasPrevious()"
        >
          Replay the old refresh token
        </button>
      }

      @if (result(); as r) {
        <table class="hd-table" aria-live="polite">
          <caption>
            What Heimdall answered, in order
          </caption>
          <thead>
            <tr>
              <th scope="col">Sent by</th>
              <th scope="col">Refresh token</th>
              <th scope="col">Answer</th>
            </tr>
          </thead>
          <tbody>
            @for (
              row of [
                { who: 'Attacker, with the old token', a: r.replay },
                { who: 'Client, with the current token', a: r.current },
              ];
              track row.who
            ) {
              <tr>
                <th scope="row">{{ row.who }}</th>
                <td>
                  <code>{{ row.a.tokenFingerprint }}</code>
                </td>
                <td>
                  <span [class]="row.a.error === null ? 'mark mark--issued' : 'mark mark--refused'">
                    {{ row.a.error === null ? 'Issued' : 'Refused' }}
                  </span>
                  HTTP {{ row.a.status }} <code>{{ row.a.error ?? '' }}</code>
                </td>
              </tr>
            }
          </tbody>
        </table>
        @switch (r.verdict) {
          @case ('family-revoked') {
            <div class="hd-confirm">
              <p class="hd-confirm__title">Reuse detected. The family is revoked.</p>
              <p>
                The current token fails too, so the attacker's copy and the client's copy are both
                dead. The client dropped its tokens and must sign in again.
              </p>
            </div>
          }
          @case ('replay-refused-only') {
            <div class="hd-problem">
              <p class="hd-problem__title">Defect</p>
              <p>
                Heimdall refused the old token but did not revoke the family. This breaks the rule
                that reuse revokes the family.
              </p>
            </div>
          }
          @case ('replay-accepted') {
            <div class="hd-problem">
              <p class="hd-problem__title">Defect</p>
              <p>Heimdall accepted a used refresh token.</p>
            </div>
          }
          @default {
            <p class="hd-note">The answers do not show a result. Check that Heimdall is running.</p>
          }
        }
      }

      @if (session.state() !== 'signed-in') {
        <button class="hd-button" type="button" (click)="session.signIn()">Sign in again</button>
      }
    </section>

    <section aria-labelledby="steal-heading">
      <h2 class="hd-heading" id="steal-heading">DPoP demo</h2>
      <p>
        The client's tokens are bound to a key pair that lives in this browser (RFC 9449). The
        private key cannot leave it, not even through script on this page.
        @if (keyThumbprint(); as jkt) {
          Key thumbprint: <code>{{ jkt }}</code
          >.
        }
      </p>
      <p>
        An attacker steals the current refresh token, before the client uses it, and sends it to the
        token endpoint without a proof. Then the client refreshes as usual, with its key.
      </p>
      @if (session.state() === 'signed-in') {
        <button class="hd-button" type="button" (click)="steal()" [disabled]="busy()">
          Steal the current refresh token
        </button>
      }

      @if (stealResult(); as s) {
        <table class="hd-table" aria-live="polite">
          <caption>
            What Heimdall answered, in order
          </caption>
          <thead>
            <tr>
              <th scope="col">Sent by</th>
              <th scope="col">Answer</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row">Attacker, with the current token and no key</th>
              <td>
                <span [class]="s.thief.error === null ? 'mark mark--issued' : 'mark mark--refused'">
                  {{ s.thief.error === null ? 'Issued' : 'Refused' }}
                </span>
                HTTP {{ s.thief.status }} <code>{{ s.thief.error ?? '' }}</code>
              </td>
            </tr>
            <tr>
              <th scope="row">Client, with its key</th>
              <td>
                <span [class]="s.clientRefreshed ? 'mark mark--issued' : 'mark mark--refused'">
                  {{ s.clientRefreshed ? 'Issued' : 'Refused' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
        @switch (s.verdict) {
          @case ('thief-needs-key') {
            <div class="hd-confirm">
              <p class="hd-confirm__title">The stolen token is useless without the key.</p>
              <p>
                Heimdall refused the attacker and did not use up the token, so the client refreshed
                as usual. Compare the replay demo above: without DPoP, the only defense is to revoke
                the whole family, and the user must sign in again.
              </p>
            </div>
          }
          @case ('thief-accepted') {
            <div class="hd-problem">
              <p class="hd-problem__title">Not bound</p>
              <p>
                Heimdall gave the attacker tokens. The family is not bound to a key: sign in again,
                so the first token request carries a proof.
              </p>
            </div>
          }
          @case ('client-locked-out') {
            <div class="hd-problem">
              <p class="hd-problem__title">Defect</p>
              <p>The attacker was refused, but the client could not refresh afterwards.</p>
            </div>
          }
          @default {
            <p class="hd-note">The answers do not show a result. Check that Heimdall is running.</p>
          }
        }
      }
    </section>
  `,
})
export class TokensPage {
  protected readonly history = inject(RefreshTokenHistory);
  protected readonly session = inject(DemoSession);
  private readonly theft = inject(TheftDemo);
  private readonly dpop = inject(DpopKeys);
  protected readonly busy = signal(false);
  protected readonly refreshError = signal(false);
  protected readonly result = signal<TheftDemoResult | null>(null);
  protected readonly stealResult = signal<StealDemoResult | null>(null);
  protected readonly keyThumbprint = signal<string | null>(null);

  constructor() {
    void this.dpop.thumbprint().then(({ jkt }) => this.keyThumbprint.set(jkt));
  }

  protected async steal(): Promise<void> {
    const current = this.history.currentToken();
    if (current === null) {
      return;
    }

    this.busy.set(true);
    try {
      this.stealResult.set(await this.theft.stealCurrent(current, () => this.session.refreshNow()));
    } finally {
      this.busy.set(false);
    }
  }

  protected async refresh(): Promise<void> {
    this.busy.set(true);
    this.refreshError.set(false);
    try {
      await this.session.refreshNow();
    } catch {
      this.refreshError.set(true);
    } finally {
      this.busy.set(false);
    }
  }

  protected async replay(): Promise<void> {
    const previous = this.history.previousToken();
    const current = this.history.currentToken();
    if (previous === null || current === null) {
      return;
    }

    this.busy.set(true);
    try {
      const result = await this.theft.run(previous, current);
      this.result.set(result);
      if (result.verdict === 'family-revoked') {
        // The library still holds revoked tokens. Drop them. The page keeps the result.
        this.session.endLocally();
      }
    } finally {
      this.busy.set(false);
    }
  }
}
