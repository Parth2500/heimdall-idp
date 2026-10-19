import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { HEIMDALL_ISSUER } from './auth.config';
import { HeimdallDiscovery } from './discovery';

const URL = `${HEIMDALL_ISSUER}/.well-known/openid-configuration`;

describe('HeimdallDiscovery', () => {
  let http: HttpTestingController;
  let discovery: HeimdallDiscovery;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpTestingController);
    discovery = TestBed.inject(HeimdallDiscovery);
  });

  afterEach(() => http.verify());

  it('reads the document once', async () => {
    const first = discovery.endpoints();
    http.expectOne(URL).flush({ issuer: HEIMDALL_ISSUER, token_endpoint: 't' });

    expect((await first).token_endpoint).toBe('t');
    expect((await discovery.endpoints()).token_endpoint).toBe('t');
    http.expectNone(URL);
  });

  it('rejects a document that names another issuer', async () => {
    const result = discovery.endpoints();
    http.expectOne(URL).flush({ issuer: 'https://evil.example', token_endpoint: 't' });

    await expect(result).rejects.toThrow('different issuer');
  });

  it('tries again after a failure', async () => {
    const failed = discovery.endpoints();
    http.expectOne(URL).flush(null, { status: 503, statusText: 'Unavailable' });
    await expect(failed).rejects.toBeDefined();

    const retry = discovery.endpoints();
    await vi.waitFor(() => http.expectOne(URL)).then((r) => r.flush({ issuer: HEIMDALL_ISSUER }));
    await expect(retry).resolves.toEqual({ issuer: HEIMDALL_ISSUER });
  });
});
