import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { SessionApi, SessionApiError } from '../session/session-api';
import { BrowserNavigation } from '../session/flow';
import { REQUEST_ID, fakeNavigation, routeWith, text } from '../testing';
import { ConsentPage } from './consent-page';

const PROMPT = {
  client_id: 'demo-spa',
  client_name: '<b>Demo</b> app',
  scopes: ['openid', 'email', 'x.custom'],
  redirect_host: 'demo.localhost:4300',
};

async function render(
  api: Partial<SessionApi>,
  settled = (root: HTMLElement) => !text(root).includes('Loading the request'),
) {
  const navigation = fakeNavigation();
  const router = { navigate: vi.fn().mockResolvedValue(true) };
  TestBed.configureTestingModule({
    providers: [
      routeWith({ request_id: REQUEST_ID }),
      { provide: SessionApi, useValue: api },
      { provide: BrowserNavigation, useValue: navigation },
      { provide: Router, useValue: router },
    ],
  });
  const fixture = TestBed.createComponent(ConsentPage);
  await vi.waitFor(async () => {
    await fixture.whenStable();
    expect(settled(fixture.nativeElement)).toBe(true);
  });
  return { fixture, root: fixture.nativeElement as HTMLElement, navigation, router };
}

describe('ConsentPage', () => {
  it('shows server values as text and fixed scope descriptions', async () => {
    const { root } = await render({ consentPrompt: vi.fn().mockResolvedValue(PROMPT) });

    expect(root.querySelector('b')).toBeNull();
    expect(text(root)).toContain('Allow <b>Demo</b> app to use your account?');
    expect(text(root)).toContain('Read your email address.');
    expect(text(root)).toContain('Use a permission that Heimdall does not describe.');
    expect(text(root)).toContain('demo.localhost:4300');
    // The label is the scope name the app asked for, never a claim name such as sub.
    const names = Array.from(root.querySelectorAll('.scope-name')).map((e) => e.textContent);
    expect(names).toEqual(['openid', 'email', 'x.custom']);
  });

  it('sends only the decision, then goes to the resume path', async () => {
    const decide = vi.fn().mockResolvedValue(undefined);
    const { fixture, root, navigation } = await render({
      consentPrompt: vi.fn().mockResolvedValue(PROMPT),
      decide,
    });

    const deny = Array.from(root.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Deny',
    )!;
    deny.click();
    await fixture.whenStable();

    expect(decide).toHaveBeenCalledWith(REQUEST_ID, false);
    expect(root.querySelector('hd-card')?.getAttribute('data-state')).toBe('refused');
    expect(navigation.assign).toHaveBeenCalledWith(
      `/oauth/v1/authorize/resume?request_id=${REQUEST_ID}`,
    );
  });

  it('goes to the login page for the same request when the session ended', async () => {
    const navigate = vi.fn().mockResolvedValue(true);
    TestBed.overrideProvider(Router, { useValue: { navigate } });
    await render(
      {
        consentPrompt: vi.fn().mockRejectedValue(new SessionApiError(401, 'login_required', null)),
      },
      () => navigate.mock.calls.length > 0,
    );
    const router = { navigate };

    expect(router.navigate).toHaveBeenCalledWith(['/login'], {
      queryParams: { request_id: REQUEST_ID },
    });
  });

  it('says that an unknown or old request has ended', async () => {
    const { root } = await render({
      consentPrompt: vi.fn().mockRejectedValue(new SessionApiError(400, 'invalid_request', null)),
    });

    expect(text(root)).toContain('This request has ended');
  });
});
