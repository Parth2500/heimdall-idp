import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { DEMO_CLIENT_ID } from '../auth/auth.config';
import { HeimdallDiscovery } from '../auth/discovery';
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
    const replay = await this.refresh(token_endpoint, previousToken);
    // Order matters: the current token is sent only after the replay, so a revoked family
    // shows up as invalid_grant on a token that was valid a moment before.
    const current = await this.refresh(token_endpoint, currentToken);
    return { replay, current, verdict: verdictOf(replay, current) };
  }

  private async refresh(tokenEndpoint: string, refreshToken: string): Promise<RefreshAttempt> {
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
