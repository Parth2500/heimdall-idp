import { FINGERPRINT_LENGTH, fingerprint } from './fingerprint';

describe('fingerprint', () => {
  it('returns the first hex characters of the SHA-256', async () => {
    // SHA-256("abc") = ba7816bf... (FIPS 180-2, appendix B.1).
    expect(await fingerprint('abc')).toBe('ba7816');
  });

  it('never returns the token itself', async () => {
    const value = await fingerprint('a-refresh-token');

    expect(value).toHaveLength(FINGERPRINT_LENGTH);
    expect('a-refresh-token').not.toContain(value);
  });
});
