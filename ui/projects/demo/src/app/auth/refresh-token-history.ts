import { Injectable, computed, signal } from '@angular/core';
import { fingerprint } from './fingerprint';

export interface Rotation {
  readonly fingerprint: string;
  readonly receivedAt: Date;
}

/**
 * Remembers the current and the previous refresh token, in memory only. The theft demo needs
 * the previous one: it plays the attacker who stole a token before the client rotated it.
 */
@Injectable({ providedIn: 'root' })
export class RefreshTokenHistory {
  private current: string | null = null;
  private previous: string | null = null;
  private readonly rotationList = signal<readonly Rotation[]>([]);

  /** Each refresh token that the client got, oldest first, as fingerprints. */
  readonly rotations = this.rotationList.asReadonly();
  readonly hasPrevious = computed(() => this.rotationList().length > 1);

  /** Records the refresh token that the client holds now. The same token again changes nothing. */
  async record(refreshToken: string, now = new Date()): Promise<void> {
    if (!refreshToken || refreshToken === this.current) {
      return;
    }

    this.previous = this.current;
    this.current = refreshToken;
    const entry: Rotation = { fingerprint: await fingerprint(refreshToken), receivedAt: now };
    this.rotationList.update((list) => [...list, entry]);
  }

  currentToken(): string | null {
    return this.current;
  }

  previousToken(): string | null {
    return this.previous;
  }

  clear(): void {
    this.current = null;
    this.previous = null;
    this.rotationList.set([]);
  }
}
