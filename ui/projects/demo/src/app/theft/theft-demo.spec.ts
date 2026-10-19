import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { HeimdallDiscovery } from '../auth/discovery';
import { RefreshAttempt, TheftDemo, verdictOf } from './theft-demo';

const TOKEN_ENDPOINT = 'https://acme.localhost:7200/oauth/v1/token';

function attempt(error: string | null, status = error === null ? 200 : 400): RefreshAttempt {
  return { tokenFingerprint: 'abcdef', status, error };
}

describe('verdictOf', () => {
  it('reports a revoked family when both tokens fail with invalid_grant', () => {
    expect(verdictOf(attempt('invalid_grant'), attempt('invalid_grant'))).toBe('family-revoked');
  });

  it('reports a defect when the replay succeeds', () => {
    expect(verdictOf(attempt(null), attempt('invalid_grant'))).toBe('replay-accepted');
  });

  it('reports a defect when the current token still works', () => {
    expect(verdictOf(attempt('invalid_grant'), attempt(null))).toBe('replay-refused-only');
  });

  it('does not guess on a network failure', () => {
    expect(verdictOf(attempt('no_error_code', 0), attempt('no_error_code', 0))).toBe(
      'inconclusive',
    );
    expect(verdictOf(attempt('invalid_grant'), attempt('no_error_code', 0))).toBe('inconclusive');
  });
});

describe('TheftDemo', () => {
  let http: HttpTestingController;
  let demo: TheftDemo;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: HeimdallDiscovery,
          useValue: { endpoints: () => Promise.resolve({ token_endpoint: TOKEN_ENDPOINT }) },
        },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    demo = TestBed.inject(TheftDemo);
  });

  afterEach(() => http.verify());

  it('sends the old token first, then the current token, as a public client', async () => {
    const run = demo.run('RT1', 'RT2');

    const replay = await vi.waitFor(() => http.expectOne(TOKEN_ENDPOINT));
    expect(replay.request.method).toBe('POST');
    expect(replay.request.headers.get('Content-Type')).toBe('application/x-www-form-urlencoded');
    const replayBody = new URLSearchParams(replay.request.body as string);
    expect(replayBody.get('grant_type')).toBe('refresh_token');
    expect(replayBody.get('refresh_token')).toBe('RT1');
    expect(replayBody.get('client_id')).toBe('demo-spa');
    expect(replayBody.has('client_secret')).toBe(false);
    replay.flush({ error: 'invalid_grant' }, { status: 400, statusText: 'Bad Request' });

    const current = await vi.waitFor(() => http.expectOne(TOKEN_ENDPOINT));
    expect(new URLSearchParams(current.request.body as string).get('refresh_token')).toBe('RT2');
    current.flush({ error: 'invalid_grant' }, { status: 400, statusText: 'Bad Request' });

    const result = await run;
    expect(result.verdict).toBe('family-revoked');
    expect(result.replay).toEqual({
      tokenFingerprint: expect.any(String),
      status: 400,
      error: 'invalid_grant',
    });
    expect(JSON.stringify(result)).not.toContain('RT1');
  });

  it('drops the tokens of an accepted replay', async () => {
    const run = demo.run('RT1', 'RT2');

    (await vi.waitFor(() => http.expectOne(TOKEN_ENDPOINT))).flush({
      access_token: 'stolen-AT',
      refresh_token: 'stolen-RT',
    });
    (await vi.waitFor(() => http.expectOne(TOKEN_ENDPOINT))).flush(
      { error: 'invalid_grant' },
      { status: 400, statusText: 'Bad Request' },
    );

    const result = await run;
    expect(result.verdict).toBe('replay-accepted');
    expect(JSON.stringify(result)).not.toContain('stolen');
  });
});
