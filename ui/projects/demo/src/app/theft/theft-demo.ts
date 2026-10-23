import { HttpClient, HttpContext, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { DEMO_CLIENT_ID } from '../auth/auth.config';
import { HeimdallDiscovery } from '../auth/discovery';
import { NO_DPOP } from '../auth/dpop';
import { fingerprint } from '../auth/fingerprint';

/** What Heimdall answered to one refresh request. */
export interface RefreshAttempt {
  readonly tokenFingerprint: string;
  readonly status: number;
  /** The OAuth `error` code, such as `invalid_grant`, or null when the request succeeded. */
  readonly error: string | null;
}

export type TheftVerdict =
  /** Both requests got `invalid_grant`: Heimdall detected the reuse and revoked the family. */
  | 'family-revoked'
  /** The replay got `invalid_grant`, but the current token still works. */
  | 'replay-refused-only'
  /** Heimdall accepted the replayed token. This is a defect. */
  | 'replay-accepted'
  /** Another answer, for example a network error. */
  | 'inconclusive';

export interface TheftDemoResult {
  readonly replay: RefreshAttempt;
  readonly current: RefreshAttempt;
  readonly verdict: TheftVerdict;
}

export type StealVerdict =
  /** The thief got invalid_dpop_proof and the client still refreshed: DPoP stopped the theft. */
  | 'thief-needs-key'
  /** Heimdall gave the thief tokens. With a bound family, this is a defect. */
  | 'thief-accepted'
  /** The thief was refused, but the client's refresh failed too: the token was used up. */
  | 'client-locked-out'
  /** Another answer, for example a network error or an unbound family. */
  | 'inconclusive';

export interface StealDemoResult {
  readonly thief: RefreshAttempt;
  /** True when the client's own refresh, with its key, worked after the attempt. */
  readonly clientRefreshed: boolean;
  readonly verdict: StealVerdict;
}

/**
 * Plays an attacker who stole a refresh token before the client rotated it. The demo sends
 * the old token, then the current one, straight to the token endpoint.
 *
 * This is the only hand-written token request in the demo. It is not client code: it imitates
 * a second party that holds a copy of the token. The library does every real token request.
 */
@Injectable({ providedIn: 'root' })
export class TheftDemo {
  private readonly http = inject(HttpClient);
  private readonly discovery = inject(HeimdallDiscovery);

  async run(previousToken: string, currentToken: string): Promise<TheftDemoResult> {
    const { token_endpoint } = await this.discovery.endpoints();
    // The attacker has no private key, so its request carries no DPoP proof.
    const replay = await this.refresh(token_endpoint, previousToken, true);
    // Order matters: the current token is sent only after the replay, so a revoked family
    // shows up as invalid_grant on a token that was valid a moment before. The client's
    // request carries a proof, as the real client's would.
    const current = await this.refresh(token_endpoint, currentToken, false);
    return { replay, current, verdict: verdictOf(replay, current) };
  }

  /**
   * Plays an attacker who stole the current refresh token, before the client used it. The
   * attacker has no private key, so it sends no DPoP proof. Then the client refreshes as usual,
   * with its key, through the library.
   */
  async stealCurrent(
    currentToken: string,
    clientRefresh: () => Promise<void>,
  ): Promise<StealDemoResult> {
    const { token_endpoint } = await this.discovery.endpoints();
    const thief = await this.refresh(token_endpoint, currentToken, true);
    let clientRefreshed = true;
    try {
      await clientRefresh();
    } catch {
      clientRefreshed = false;
    }
    return { thief, clientRefreshed, verdict: stealVerdictOf(thief, clientRefreshed) };
  }

  private async refresh(
    tokenEndpoint: string,
    refreshToken: string,
    attacker: boolean,
  ): Promise<RefreshAttempt> {
    // A public client sends client_id in the body and no secret (RFC 6749, section 3.2.1).
    const body = new HttpParams()
      .set('grant_type', 'refresh_token')
      .set('refresh_token', refreshToken)
      .set('client_id', DEMO_CLIENT_ID);
    const tokenFingerprint = await fingerprint(refreshToken);

    try {
      const response = await firstValueFrom(
        this.http.post(tokenEndpoint, body.toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          observe: 'response',
          context: new HttpContext().set(NO_DPOP, attacker),
        }),
      );
      // The response body holds new tokens. The demo drops them: the attacker's tokens
      // must not replace the client's tokens.
      return { tokenFingerprint, status: response.status, error: null };
    } catch (e) {
      if (e instanceof HttpErrorResponse) {
        return { tokenFingerprint, status: e.status, error: errorCodeOf(e.error) };
      }
      throw e;
    }
  }
}

export function verdictOf(replay: RefreshAttempt, current: RefreshAttempt): TheftVerdict {
  if (replay.error === null) {
    return 'replay-accepted';
  }
  if (replay.error !== 'invalid_grant') {
    return 'inconclusive';
  }
  if (current.error === 'invalid_grant') {
    return 'family-revoked';
  }
  return current.error === null ? 'replay-refused-only' : 'inconclusive';
}

export function stealVerdictOf(thief: RefreshAttempt, clientRefreshed: boolean): StealVerdict {
  if (thief.error === null) {
    return 'thief-accepted';
  }
  if (thief.error !== 'invalid_dpop_proof') {
    return 'inconclusive';
  }
  return clientRefreshed ? 'thief-needs-key' : 'client-locked-out';
}

function errorCodeOf(body: unknown): string {
  if (
    typeof body === 'object' &&
    body !== null &&
    'error' in body &&
    typeof body.error === 'string'
  ) {
    return body.error;
  }
  return 'no_error_code';
}
