import { REDIRECT_KEYS, SplitSecurityStorage } from './split-storage';

describe('SplitSecurityStorage', () => {
  let session: Storage;
  let storage: SplitSecurityStorage;

  beforeEach(() => {
    session = window.sessionStorage;
    session.clear();
    storage = new SplitSecurityStorage(session);
  });

  it('never writes a token to sessionStorage', () => {
    storage.write(
      'demo',
      JSON.stringify({
        authnResult: { access_token: 'AT', refresh_token: 'RT', id_token: 'IT' },
        authzData: 'AT',
        reusable_refresh_token: 'RT',
        codeVerifier: 'verifier',
      }),
    );

    const stored = session.getItem('heimdall-demo.flow.demo') ?? '';
    expect(stored).not.toContain('AT');
    expect(stored).not.toContain('RT');
    expect(stored).not.toContain('IT');
    expect(JSON.parse(stored)).toEqual({ codeVerifier: 'verifier' });
  });

  it('keeps the sign-in request values through a reload', () => {
    const flow = Object.fromEntries(REDIRECT_KEYS.map((k) => [k, `${k}-value`]));
    storage.write('demo', JSON.stringify({ ...flow, authnResult: { refresh_token: 'RT' } }));

    // A reload makes a new instance with empty memory.
    const afterReload = new SplitSecurityStorage(session);

    expect(JSON.parse(afterReload.read('demo') ?? '{}')).toEqual(flow);
  });

  it('merges memory and sessionStorage on read', () => {
    storage.write('demo', JSON.stringify({ codeVerifier: 'v', authzData: 'AT' }));

    expect(JSON.parse(storage.read('demo') ?? '{}')).toEqual({
      codeVerifier: 'v',
      authzData: 'AT',
    });
  });

  it('removes the session entry when no request values are left', () => {
    storage.write('demo', JSON.stringify({ codeVerifier: 'v' }));
    storage.write('demo', JSON.stringify({ authzData: 'AT' }));

    expect(session.getItem('heimdall-demo.flow.demo')).toBeNull();
  });

  it('returns null when nothing is stored', () => {
    expect(storage.read('demo')).toBeNull();
  });

  it('clears entries that an earlier page load wrote', () => {
    storage.write('demo', JSON.stringify({ codeVerifier: 'v' }));
    session.setItem('unrelated', 'x');

    new SplitSecurityStorage(session).clear();

    expect(session.getItem('heimdall-demo.flow.demo')).toBeNull();
    expect(session.getItem('unrelated')).toBe('x');
  });
});
