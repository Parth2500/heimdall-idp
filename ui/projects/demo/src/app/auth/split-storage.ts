import { AbstractSecurityStorage } from 'angular-auth-oidc-client';

/**
 * The library keys that must live through the redirect to Heimdall and back. The browser
 * loads the page again at /callback, so memory is empty there. Without these values the
 * library cannot check `state` or send the PKCE `code_verifier`.
 *
 * This is an allowlist. A key that is not here stays in memory, so a new token key in a
 * later library version never lands in web storage by default.
 */
export const REDIRECT_KEYS: readonly string[] = [
  'authStateControl',
  'authNonce',
  'codeVerifier',
  'storageCodeFlowInProgress',
  'storageCustomParamsAuthRequest',
];

const SESSION_PREFIX = 'heimdall-demo.flow.';

type Entries = Record<string, unknown>;

/**
 * Keeps tokens in memory only (U10). Script on the page can read web storage, so an XSS bug
 * would leak a stored refresh token. Only the values of one sign-in request go to
 * sessionStorage, and the library removes them after the callback.
 *
 * The library stores one JSON object for each configuration ID. This class splits each object
 * by key.
 */
export class SplitSecurityStorage implements AbstractSecurityStorage {
  private readonly memory = new Map<string, Entries>();

  constructor(private readonly session: Storage) {}

  read(configId: string): string | null {
    const merged = { ...this.readSession(configId), ...this.memory.get(configId) };
    return Object.keys(merged).length === 0 ? null : JSON.stringify(merged);
  }

  write(configId: string, value: string): void {
    const entries = (JSON.parse(value) ?? {}) as Entries;
    const forSession: Entries = {};
    const forMemory: Entries = {};
    for (const [key, entry] of Object.entries(entries)) {
      (REDIRECT_KEYS.includes(key) ? forSession : forMemory)[key] = entry;
    }

    this.memory.set(configId, forMemory);
    if (Object.keys(forSession).length === 0) {
      this.session.removeItem(this.sessionKey(configId));
    } else {
      this.session.setItem(this.sessionKey(configId), JSON.stringify(forSession));
    }
  }

  remove(configId: string): void {
    this.memory.delete(configId);
    this.session.removeItem(this.sessionKey(configId));
  }

  clear(): void {
    this.memory.clear();
    // After a reload, memory does not know the configuration IDs, so look at the stored keys.
    const ours: string[] = [];
    for (let i = 0; i < this.session.length; i++) {
      const key = this.session.key(i);
      if (key?.startsWith(SESSION_PREFIX)) {
        ours.push(key);
      }
    }
    ours.forEach((key) => this.session.removeItem(key));
  }

  private readSession(configId: string): Entries {
    const raw = this.session.getItem(this.sessionKey(configId));
    return raw === null ? {} : (JSON.parse(raw) as Entries);
  }

  private sessionKey(configId: string): string {
    return SESSION_PREFIX + configId;
  }
}
