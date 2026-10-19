import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { DemoSession } from '../auth/demo-session';
import { RefreshTokenHistory } from '../auth/refresh-token-history';
import { TheftDemo, TheftDemoResult } from '../theft/theft-demo';

/** The refresh screen and the theft demo screen of U11. */
@Component({
  selector: 'demo-tokens-page',
  imports: [DatePipe],
  template: `
    <h1>Refresh and theft</h1>

    @if (session.state() === 'signed-in') {
      <section aria-labelledby="refresh-heading">
        <h2 id="refresh-heading">Refresh token rotation</h2>
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
        <button type="button" (click)="refresh()" [disabled]="busy()">Refresh now</button>
        @if (refreshError()) {
          <p role="alert" class="notice">
            The refresh failed. Sign in again to get a new token family.
          </p>
        }
      </section>
    }

    <section aria-labelledby="theft-heading">
      <h2 id="theft-heading">Theft demo</h2>
      <p>
        An attacker who copied the previous refresh token now sends it to the token endpoint. Then
        the demo sends the current token, as the real client would.
      </p>
      @if (session.state() === 'signed-in') {
        @if (!history.hasPrevious()) {
          <p>Refresh once first, so that a used token exists.</p>
        }
        <button type="button" (click)="replay()" [disabled]="busy() || !history.hasPrevious()">
          Replay the old refresh token
        </button>
      } @else {
        <button type="button" (click)="session.signIn()">Sign in again</button>
      }

      @if (result(); as r) {
        <ol class="steps" aria-live="polite">
          <li>
            Old token <code>{{ r.replay.tokenFingerprint }}</code
            >: HTTP {{ r.replay.status }},
            <code>{{ r.replay.error ?? 'tokens issued' }}</code>
          </li>
          <li>
            Current token <code>{{ r.current.tokenFingerprint }}</code
            >: HTTP {{ r.current.status }},
            <code>{{ r.current.error ?? 'tokens issued' }}</code>
          </li>
        </ol>
        @switch (r.verdict) {
          @case ('family-revoked') {
            <p class="verdict">
              Heimdall detected the reuse and revoked the whole token family. The current token
              fails too, so the attacker's copy and the client's copy are both dead. The client
              dropped its tokens and must sign in again.
            </p>
          }
          @case ('replay-refused-only') {
            <p class="verdict defect">
              Heimdall refused the old token but did not revoke the family. This breaks the rule
              that reuse revokes the family.
            </p>
          }
          @case ('replay-accepted') {
            <p class="verdict defect">Heimdall accepted a used refresh token. This is a defect.</p>
          }
          @default {
            <p class="verdict">The answers do not show a result. Check that Heimdall is running.</p>
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
  protected readonly busy = signal(false);
  protected readonly refreshError = signal(false);
  protected readonly result = signal<TheftDemoResult | null>(null);

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
