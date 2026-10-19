/** The number of hex characters that the demo shows for a token. */
export const FINGERPRINT_LENGTH = 6;

/**
 * Returns the first characters of the SHA-256 of a token, in hex. The page shows this value,
 * never the token: a reviewer can see that a token changed, and a screenshot leaks nothing
 * that a caller can use.
 */
export async function fingerprint(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, FINGERPRINT_LENGTH);
}
