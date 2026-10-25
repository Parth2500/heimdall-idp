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

/**
 * The sealed sign-out request from the page address, or null (U17). The page never opens it. It
 * only sends it back, so any value that is not plain URL-safe text is dropped.
 */
export function logoutRequestOrNull(value: string | null | undefined): string | null {
  return value && value.length <= 4096 && /^[A-Za-z0-9_-]+$/.test(value) ? value : null;
}

/**
 * True for a place that Heimdall's answer may name after a sign-out: an absolute http(s) URL (a
 * registered post-logout redirect URI) or a path on this origin. Never a script URL.
 */
export function isSafeDestination(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  if (value.startsWith('/')) {
    return !value.startsWith('//') && !value.startsWith('/\\');
  }
  return /^https?:\/\//i.test(value);
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
