import { RefreshTokenHistory } from './refresh-token-history';

describe('RefreshTokenHistory', () => {
  let history: RefreshTokenHistory;

  beforeEach(() => (history = new RefreshTokenHistory()));

  it('keeps the previous token after a rotation', async () => {
    await history.record('RT1');
    await history.record('RT2');

    expect(history.previousToken()).toBe('RT1');
    expect(history.currentToken()).toBe('RT2');
    expect(history.rotations()).toHaveLength(2);
    expect(history.hasPrevious()).toBe(true);
  });

  it('ignores the same token and an empty token', async () => {
    await history.record('RT1');
    await history.record('RT1');
    await history.record('');

    expect(history.rotations()).toHaveLength(1);
    expect(history.previousToken()).toBeNull();
    expect(history.hasPrevious()).toBe(false);
  });

  it('exposes fingerprints, not tokens', async () => {
    await history.record('RT1');

    expect(JSON.stringify(history.rotations())).not.toContain('RT1');
  });

  it('forgets everything on clear', async () => {
    await history.record('RT1');
    await history.record('RT2');
    history.clear();

    expect(history.currentToken()).toBeNull();
    expect(history.previousToken()).toBeNull();
    expect(history.rotations()).toEqual([]);
  });
});
