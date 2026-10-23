import { HttpClient, HttpContext, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { HeimdallDiscovery } from './discovery';
import { DpopKeys, NO_DPOP, dpopInterceptor, sha256Base64Url, thumbprintOf } from './dpop';

const TOKEN_ENDPOINT = 'https://acme.localhost:7200/oauth/v1/token';

function decode(segment: string): Record<string, unknown> {
  return JSON.parse(atob(segment.replace(/-/g, '+').replace(/_/g, '/')));
}

function base64UrlToBytes(segment: string): Uint8Array<ArrayBuffer> {
  const binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

describe('thumbprintOf', () => {
  it('hashes the required members in lexical order (RFC 7638)', async () => {
    // The expected value comes from an independent SHA-256 over the canonical JSON.
    const jkt = await thumbprintOf({
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    });

    expect(jkt).toBe('oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U');
  });
});

describe('sha256Base64Url', () => {
  it('gives the ath of an access token', async () => {
    expect(await sha256Base64Url('the.access.token')).toBe(
      'R2a7yCsxS8BpCgk-2VRP3xHZJ8n6zSvOygTlU97Z9m0',
    );
  });
});

describe('DpopKeys', () => {
  it('signs an ES256 proof that verifies with the public key in its header', async () => {
    const keys = new DpopKeys();

    const proof = await keys.proof(
      'GET',
      'https://acme.localhost:7200/oauth/v1/userinfo?x=1#y',
      'AT',
    );

    const [h, p, s] = proof.split('.');
    const header = decode(h);
    const payload = decode(p);
    expect(header['typ']).toBe('dpop+jwt');
    expect(header['alg']).toBe('ES256');
    expect(Object.keys(header['jwk'] as object).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(payload['htm']).toBe('GET');
    expect(payload['htu']).toBe('https://acme.localhost:7200/oauth/v1/userinfo');
    expect(payload['ath']).toBe(await sha256Base64Url('AT'));
    expect(typeof payload['jti']).toBe('string');

    const publicKey = await crypto.subtle.importKey(
      'jwk',
      header['jwk'] as JsonWebKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      base64UrlToBytes(s),
      new TextEncoder().encode(`${h}.${p}`),
    );
    expect(valid).toBe(true);
  });

  it('uses one key for every proof and names it by its thumbprint', async () => {
    const keys = new DpopKeys();

    const first = decode((await keys.proof('POST', TOKEN_ENDPOINT)).split('.')[0]);
    const second = decode((await keys.proof('POST', TOKEN_ENDPOINT)).split('.')[0]);
    const { jkt } = await keys.thumbprint();

    expect(first['jwk']).toEqual(second['jwk']);
    expect(jkt).toBe(await thumbprintOf(first['jwk'] as never));
  });
});

describe('dpopInterceptor', () => {
  let http: HttpClient;
  let backend: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([dpopInterceptor])),
        provideHttpClientTesting(),
        {
          provide: HeimdallDiscovery,
          useValue: { endpoints: () => Promise.resolve({ token_endpoint: TOKEN_ENDPOINT }) },
        },
      ],
    });
    http = TestBed.inject(HttpClient);
    backend = TestBed.inject(HttpTestingController);
  });

  afterEach(() => backend.verify());

  it('adds a proof for this endpoint to a POST to the token endpoint', async () => {
    const done = firstValueFrom(http.post(TOKEN_ENDPOINT, 'grant_type=refresh_token'));

    const req = await vi.waitFor(() => backend.expectOne(TOKEN_ENDPOINT));
    const payload = decode(req.request.headers.get('DPoP')!.split('.')[1]);
    expect(payload['htm']).toBe('POST');
    expect(payload['htu']).toBe(TOKEN_ENDPOINT);
    req.flush({});
    await done;
  });

  it('sends no proof for a request marked NO_DPOP, or to another endpoint', async () => {
    const attacker = firstValueFrom(
      http.post(TOKEN_ENDPOINT, '', { context: new HttpContext().set(NO_DPOP, true) }),
    );
    const other = firstValueFrom(http.post('https://acme.localhost:7200/oauth/v1/revoke', ''));

    const a = await vi.waitFor(() => backend.expectOne(TOKEN_ENDPOINT));
    const o = await vi.waitFor(() =>
      backend.expectOne('https://acme.localhost:7200/oauth/v1/revoke'),
    );
    expect(a.request.headers.has('DPoP')).toBe(false);
    expect(o.request.headers.has('DPoP')).toBe(false);
    a.flush({});
    o.flush({});
    await Promise.all([attacker, other]);
  });
});
