import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, firstValueFrom } from 'rxjs';

/** The session API of Heimdall (`/session/v1`). Same origin and relative URLs only (U7). */
export const SESSION_API = '/session/v1';

/** What the consent page shows. Every value comes from the stored request on the server (U5). */
export interface ConsentPrompt {
  readonly client_id: string;
  readonly client_name: string;
  readonly scopes: readonly string[];
  readonly redirect_host: string;
}

/** A failed call: the HTTP status, the `error` code of the body, and `Retry-After` in seconds. */
export class SessionApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
    readonly retryAfterSeconds: number | null,
  ) {
    super(`Session API error ${status} ${code ?? ''}`.trim());
  }

  static from(error: unknown): SessionApiError {
    if (!(error instanceof HttpErrorResponse)) {
      return new SessionApiError(0, null, null);
    }
    const body = error.error as { error?: unknown } | null;
    const code = typeof body?.error === 'string' ? body.error : null;
    const retry = Number.parseInt(error.headers?.get('Retry-After') ?? '', 10);
    return new SessionApiError(
      error.status,
      code,
      Number.isFinite(retry) && retry >= 0 ? retry : null,
    );
  }
}

@Injectable({ providedIn: 'root' })
export class SessionApi {
  private readonly http = inject(HttpClient);

  /**
   * Sets the antiforgery cookie. Angular then copies it into the `X-XSRF-TOKEN` header of each
   * POST (double submit).
   */
  csrf(): Promise<void> {
    return this.call(this.http.get<void>(`${SESSION_API}/csrf`));
  }

  login(email: string, password: string): Promise<void> {
    return this.call(this.http.post<void>(`${SESSION_API}/login`, { email, password }));
  }

  consentPrompt(requestId: string): Promise<ConsentPrompt> {
    return this.call(
      this.http.get<ConsentPrompt>(`${SESSION_API}/consent`, { params: { request_id: requestId } }),
    );
  }

  /**
   * Ends the Heimdall session after the user confirms (D31). The page sends back only the sealed
   * value that Heimdall gave it (U17). The answer names where the browser goes next.
   */
  logout(logoutRequest: string | null): Promise<{ readonly redirect_to: string }> {
    return this.call(
      this.http.post<{ readonly redirect_to: string }>(`${SESSION_API}/logout`, {
        logout_request: logoutRequest,
      }),
    );
  }

  /** Sends the decision only. The server knows the client and the scopes (U5). */
  decide(requestId: string, approve: boolean): Promise<void> {
    return this.call(
      this.http.post<void>(`${SESSION_API}/consent`, { request_id: requestId, approve }),
    );
  }

  private async call<T>(request: Observable<T>): Promise<T> {
    try {
      return await firstValueFrom(request);
    } catch (e) {
      throw SessionApiError.from(e);
    }
  }
}
