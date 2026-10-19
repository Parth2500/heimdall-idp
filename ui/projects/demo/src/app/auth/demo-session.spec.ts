import { TestBed } from '@angular/core/testing';
import { OidcSecurityService, PublicEventsService } from 'angular-auth-oidc-client';
import { EMPTY, of } from 'rxjs';
import { HeimdallDiscovery } from './discovery';
import { DemoSession, RESUME_FLAG, knownErrorOrUnknown } from './demo-session';

const APP = 'https://demo.localhost:4300';

describe('knownErrorOrUnknown', () => {
  it('passes a code from the fixed list', () => {
    expect(knownErrorOrUnknown('access_denied')).toBe('access_denied');
  });

  it('replaces any other value, so the page never prints attacker text', () => {
    expect(knownErrorOrUnknown('<script>alert(1)</script>')).toBe('unknown_error');
  });

  it('keeps null as null', () => {
    expect(knownErrorOrUnknown(null)).toBeNull();
  });
});

describe('DemoSession.start', () => {
  let oidc: {
    checkAuth: ReturnType<typeof vi.fn>;
    authorize: ReturnType<typeof vi.fn>;
    getRefreshToken: ReturnType<typeof vi.fn>;
  };
  let session: DemoSession;
  let endpoints: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    endpoints = vi.fn().mockResolvedValue({});
    sessionStorage.clear();
    oidc = {
      checkAuth: vi.fn(),
      authorize: vi.fn(),
      getRefreshToken: vi.fn(() => of('RT1')),
    };
    TestBed.configureTestingModule({
      providers: [
        { provide: OidcSecurityService, useValue: oidc },
        { provide: PublicEventsService, useValue: { registerForEvents: () => EMPTY } },
        { provide: HeimdallDiscovery, useValue: { endpoints } },
      ],
    });
    session = TestBed.inject(DemoSession);
  });

  it('signs in after a valid callback and sets the resume flag', async () => {
    oidc.checkAuth.mockReturnValue(of({ isAuthenticated: true }));

    await session.start(`${APP}/callback?code=c&state=s`);

    expect(session.state()).toBe('signed-in');
    expect(sessionStorage.getItem(RESUME_FLAG)).toBe('1');
  });

  it('goes back to /authorize after a reload when the flag is set', async () => {
    sessionStorage.setItem(RESUME_FLAG, '1');
    oidc.checkAuth.mockReturnValue(of({ isAuthenticated: false }));

    await session.start(`${APP}/tokens`);

    expect(oidc.authorize).toHaveBeenCalledOnce();
    // The flag is gone, so a failed sign-in cannot start a redirect loop.
    expect(sessionStorage.getItem(RESUME_FLAG)).toBeNull();
  });

  it('stays signed out and shows the code when Heimdall sends an error', async () => {
    sessionStorage.setItem(RESUME_FLAG, '1');
    oidc.checkAuth.mockReturnValue(of({ isAuthenticated: false }));

    await session.start(`${APP}/callback?error=access_denied&state=s`);

    expect(oidc.authorize).not.toHaveBeenCalled();
    expect(session.state()).toBe('signed-out');
    expect(session.error()).toBe('access_denied');
  });

  it('stays signed out on a first visit', async () => {
    oidc.checkAuth.mockReturnValue(of({ isAuthenticated: false }));

    await session.start(`${APP}/`);

    expect(oidc.authorize).not.toHaveBeenCalled();
    expect(session.state()).toBe('signed-out');
  });

  it('says that Heimdall is unreachable instead of waiting forever', async () => {
    endpoints.mockRejectedValue(new Error('certificate not accepted'));

    await session.signIn();

    expect(oidc.authorize).not.toHaveBeenCalled();
    expect(session.unreachable()).toBe(true);
    expect(session.state()).toBe('signed-out');
  });

  it('goes to /authorize when discovery answers', async () => {
    await session.signIn();

    expect(oidc.authorize).toHaveBeenCalledOnce();
    expect(session.unreachable()).toBe(false);
  });
});
