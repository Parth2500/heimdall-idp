import { Injectable, inject, signal } from '@angular/core';
import { EventTypes, OidcSecurityService, PublicEventsService } from 'angular-auth-oidc-client';
import { filter, firstValueFrom } from 'rxjs';
import { HeimdallDiscovery } from './discovery';
import { DpopKeys } from './dpop';
import { RefreshTokenHistory } from './refresh-token-history';

/**
 * A flag in sessionStorage that says "the user was signed in before this reload". It holds no
 * token and no claim. With it, a reload goes back to /authorize at once (U10), and Heimdall
 * answers with a new code while its session cookie is valid.
 */
export const RESUME_FLAG = 'heimdall-demo.resume';

export type SessionState = 'starting' | 'signed-out' | 'signed-in' | 'redirecting';

/** The OAuth `error` codes that the demo names. Any other value shows as `unknown_error` (U6). */
export const KNOWN_ERRORS: readonly string[] = [
  'access_denied',
  'invalid_request',
  'invalid_scope',
  'unauthorized_client',
  'unsupported_response_type',
  'server_error',
  'temporarily_unavailable',
  'login_required',
  'consent_required',
];

export function knownErrorOrUnknown(code: string | null): string | null {
  if (code === null) {
    return null;
  }
  return KNOWN_ERRORS.includes(code) ? code : 'unknown_error';
}

/** The sign-in state of the demo, on top of the library. */
@Injectable({ providedIn: 'root' })
export class DemoSession {
  private readonly oidc = inject(OidcSecurityService);
  private readonly events = inject(PublicEventsService);
  private readonly history = inject(RefreshTokenHistory);
  private readonly discovery = inject(HeimdallDiscovery);
  private readonly dpop = inject(DpopKeys);
  private readonly stateSignal = signal<SessionState>('starting');
  private readonly errorSignal = signal<string | null>(null);

  readonly state = this.stateSignal.asReadonly();
  /** An OAuth error code from the last sign-in attempt, from the fixed list only. */
  readonly error = this.errorSignal.asReadonly();
  /** Goes up by one each time the client gets new tokens. Pages read the tokens again then. */
  readonly tokenVersion = signal(0);
  /** True after the user signed out in this page. The home page then explains what stays. */
  readonly signedOutHere = signal(false);
  /** True when the last sign-in could not read Heimdall's discovery document. */
  readonly unreachable = signal(false);

  /** Runs once when the application starts. It finishes a callback when the URL holds one. */
  async start(url: string): Promise<void> {
    this.events
      .registerForEvents()
      .pipe(filter((e) => e.type === EventTypes.NewAuthenticationResult))
      .subscribe(() => void this.recordRefreshToken());

    // The authorization response puts `error` in the query when the user denies consent.
    this.errorSignal.set(knownErrorOrUnknown(new URL(url).searchParams.get('error')));

    const result = await firstValueFrom(this.oidc.checkAuth(url));
    if (result.isAuthenticated) {
      sessionStorage.setItem(RESUME_FLAG, '1');
      await this.recordRefreshToken();
      this.stateSignal.set('signed-in');
      return;
    }

    if (sessionStorage.getItem(RESUME_FLAG) !== null && this.errorSignal() === null) {
      // Remove the flag first. If Heimdall sends an error back, the next load does not loop.
      sessionStorage.removeItem(RESUME_FLAG);
      await this.signIn();
      return;
    }

    this.stateSignal.set('signed-out');
  }

  /**
   * Sends the browser to /authorize. The library reads discovery first and ignores a failure,
   * so the page would wait forever. The demo checks discovery itself and says what went wrong.
   * In development the usual cause is a certificate that the browser has not accepted yet.
   */
  async signIn(): Promise<void> {
    this.stateSignal.set('redirecting');
    this.errorSignal.set(null);
    this.signedOutHere.set(false);
    this.unreachable.set(false);
    try {
      await this.discovery.endpoints();
    } catch {
      this.unreachable.set(true);
      this.stateSignal.set('signed-out');
      return;
    }
    // dpop_jkt binds the code to the key (RFC 9449, section 10). Only a key that survives the
    // redirect can redeem it, so a key in memory only sends no dpop_jkt.
    const { jkt, persisted } = await this.dpop.thumbprint();
    this.oidc.authorize(undefined, persisted ? { customParams: { dpop_jkt: jkt } } : undefined);
  }

  /** Asks the library for new tokens now. The library sends the refresh token. */
  async refreshNow(): Promise<void> {
    await firstValueFrom(this.oidc.forceRefreshSession());
    await this.recordRefreshToken();
  }

  /**
   * Revokes the refresh token at Heimdall (RFC 7009), then drops every token in memory.
   * The Heimdall session cookie stays until RP-initiated logout exists (U14).
   */
  async signOut(): Promise<void> {
    try {
      await firstValueFrom(this.oidc.revokeRefreshToken());
    } finally {
      this.endLocally();
      this.signedOutHere.set(true);
    }
  }

  /** Drops every token in memory without a call to Heimdall. */
  endLocally(): void {
    sessionStorage.removeItem(RESUME_FLAG);
    this.oidc.logoffLocal();
    this.history.clear();
    this.stateSignal.set('signed-out');
  }

  private async recordRefreshToken(): Promise<void> {
    const token = await firstValueFrom(this.oidc.getRefreshToken());
    await this.history.record(token);
    this.tokenVersion.update((v) => v + 1);
  }
}
