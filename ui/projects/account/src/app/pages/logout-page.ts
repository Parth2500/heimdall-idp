import { Component, computed, inject, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { CardState, HdIcon } from 'ui-kit';
import { SessionApi } from '../session/session-api';
import { BrowserNavigation, isSafeDestination, logoutRequestOrNull } from '../session/flow';
import { PageFrame } from './page-frame';

/**
 * The sign-out confirmation (D31, U17). Heimdall sends the browser here when a sign-out request
 * does not prove that it comes from an app of this session. Only the click ends the session, so a
 * link on another site cannot sign the user out.
 */
@Component({
  selector: 'acct-logout-page',
  imports: [PageFrame, HdIcon],
  template: `
    <acct-page [state]="cardState()">
      <div hdStatement>
        <h1 class="hd-title">Sign out of Heimdall?</h1>
        <p class="hd-subtitle">An app asked to end your Heimdall session.</p>
      </div>

      <p class="hd-lead">
        When you sign out, Heimdall ends your session on this browser. Apps that you signed in to
        through this session lose access. The next sign-in asks for your password.
      </p>

      @if (problem()) {
        <div class="hd-problem" role="alert">
          <hd-icon class="hd-problem__icon" name="alert" />
          <p class="hd-problem__title">There is a problem</p>
          <p>Heimdall did not sign you out. Check your connection, then try again.</p>
        </div>
      }

      <div class="hd-actions">
        <button
          class="hd-button hd-button--block"
          type="button"
          [attr.aria-disabled]="busy()"
          (click)="signOut()"
        >
          Sign out
        </button>
      </div>
      <p class="hd-small hd-muted">To stay signed in, close this tab.</p>
    </acct-page>
  `,
})
export class LogoutPage {
  private readonly api = inject(SessionApi);
  private readonly navigation = inject(BrowserNavigation);

  /** Sent back unchanged. The page never reads a return address from its URL (U4). */
  private readonly logoutRequest = logoutRequestOrNull(
    inject(ActivatedRoute).snapshot.queryParamMap.get('logout_request'),
  );

  protected readonly busy = signal(false);
  protected readonly problem = signal(false);
  private readonly done = signal(false);

  protected readonly cardState = computed<CardState>(() =>
    this.done() ? 'crossing' : this.busy() ? 'busy' : 'idle',
  );

  protected async signOut(): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(false);
    try {
      const result = await this.api.logout(this.logoutRequest);
      this.done.set(true);
      this.navigation.assign(
        isSafeDestination(result?.redirect_to) ? result.redirect_to : '/account/signed-out',
      );
    } catch {
      this.busy.set(false);
      this.problem.set(true);
    }
  }
}
