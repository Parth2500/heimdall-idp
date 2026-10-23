import { HttpContextToken, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { from, switchMap } from 'rxjs';
import { HeimdallDiscovery } from './discovery';

/**
 * Marks a request that must go without a DPoP proof. The theft demo sets it: the attacker has
 * the stolen token, but not the private key.
 */
export const NO_DPOP = new HttpContextToken<boolean>(() => false);

/** The members of an EC public key in a JWK. */
export interface EcPublicJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
}

const DB_NAME = 'heimdall-demo';
const STORE = 'keys';
const KEY_ID = 'dpop';

/**
 * The demo's DPoP key pair (RFC 9449). The private key is non-extractable: script on the page
 * can sign with it, but it can never read it out, so an XSS bug cannot copy the key to another
 * machine. The pair lives in IndexedDB, because the browser leaves the page for /authorize and
 * the key must still exist at the callback, where the code (bound by `dpop_jkt`) is redeemed.
 *
 * When IndexedDB fails (a private window, blocked site data), the key lives in memory only. The
 * demo then sends no `dpop_jkt`, because a new page after the redirect would have another key.
 * The tokens are still bound from the first token request on.
 */
@Injectable({ providedIn: 'root' })
export class DpopKeys {
  private keyPair: Promise<{ pair: CryptoKeyPair; persisted: boolean }> | null = null;

  /** The RFC 7638 thumbprint of the public key, and whether the key survives a page load. */
  async thumbprint(): Promise<{ jkt: string; persisted: boolean }> {
    const { pair, persisted } = await this.load();
    return { jkt: await thumbprintOf(await publicJwk(pair.publicKey)), persisted };
  }

  /**
   * A DPoP proof for one request (RFC 9449, section 4.2).
   * @param accessToken At a resource, the token that the proof goes with. Its hash is `ath`.
   */
  async proof(htm: string, htu: string, accessToken?: string): Promise<string> {
    const { pair } = await this.load();
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: await publicJwk(pair.publicKey) };
    const payload: Record<string, unknown> = {
      jti: crypto.randomUUID(),
      htm,
      htu: withoutQueryAndFragment(htu),
      iat: Math.floor(Date.now() / 1000),
    };
    if (accessToken !== undefined) {
      payload['ath'] = await sha256Base64Url(accessToken);
    }
    const input = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
    // WebCrypto ECDSA returns r || s, the JWS form of ES256 (RFC 7518, section 3.4).
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      new TextEncoder().encode(input),
    );
    return `${input}.${base64Url(new Uint8Array(signature))}`;
  }

  private load(): Promise<{ pair: CryptoKeyPair; persisted: boolean }> {
    this.keyPair ??= loadOrCreate();
    return this.keyPair;
  }
}

async function loadOrCreate(): Promise<{ pair: CryptoKeyPair; persisted: boolean }> {
  try {
    const stored = await idbGet();
    if (stored) {
      return { pair: stored, persisted: true };
    }
    const pair = await generate();
    await idbPut(pair);
    return { pair, persisted: true };
  } catch {
    return { pair: await generate(), persisted: false };
  }
}

function generate(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
}

/** A public key is always exportable, even when its private key is not. */
async function publicJwk(key: CryptoKey): Promise<EcPublicJwk> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return { kty: 'EC', crv: 'P-256', x: jwk.x!, y: jwk.y! };
}

/** RFC 7638: SHA-256 over the required members, in lexical order, with no white space. */
export async function thumbprintOf(jwk: EcPublicJwk): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return sha256Base64Url(canonical);
}

export async function sha256Base64Url(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return base64Url(new Uint8Array(digest));
}

function base64UrlJson(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** RFC 9449, section 4.2: `htu` is the URL without query and fragment. */
function withoutQueryAndFragment(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

function idbOpen(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet(): Promise<CryptoKeyPair | undefined> {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(KEY_ID);
    request.onsuccess = () => resolve(request.result as CryptoKeyPair | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function idbPut(pair: CryptoKeyPair): Promise<void> {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(pair, KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Adds a DPoP proof to each POST to Heimdall's token endpoint, so the library's code redemption
 * and refresh requests are bound to the key. A request marked with {@link NO_DPOP} goes as it is.
 */
export const dpopInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.method !== 'POST' || req.context.get(NO_DPOP)) {
    return next(req);
  }
  const keys = inject(DpopKeys);
  const discovery = inject(HeimdallDiscovery);
  return from(discovery.endpoints()).pipe(
    switchMap(({ token_endpoint }) =>
      req.url !== token_endpoint
        ? next(req)
        : from(keys.proof('POST', token_endpoint)).pipe(
            switchMap((proof) => next(req.clone({ setHeaders: { DPoP: proof } }))),
          ),
    ),
  );
};
