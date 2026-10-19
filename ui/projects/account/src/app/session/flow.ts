import { Injectable } from '@angular/core';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Returns the value when it is a UUID, else null. The pages accept no other `request_id` (U4). */
export function requestIdOrNull(value: string | null | undefined): string | null {
  return value && UUID.test(value) ? value.toLowerCase() : null;
}

/**
 * The only place the pages send the browser after a decision: the fixed resume path with the
 * stored request ID. No return URL ever comes from the browser (U4).
 */
export function resumePath(requestId: string): string {
  return `/oauth/v1/authorize/resume?request_id=${encodeURIComponent(requestId)}`;
}

/** Leaves the Angular app. A class, so tests can replace it. */
@Injectable({ providedIn: 'root' })
export class BrowserNavigation {
  assign(path: string): void {
    window.location.assign(path);
  }

  host(): string {
    return window.location.host;
  }
}
