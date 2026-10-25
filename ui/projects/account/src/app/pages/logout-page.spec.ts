import { TestBed } from '@angular/core/testing';
import { SessionApi, SessionApiError } from '../session/session-api';
import { BrowserNavigation } from '../session/flow';
import { fakeNavigation, routeWith, text } from '../testing';
import { LogoutPage } from './logout-page';

async function render(
  api: Partial<SessionApi>,
  query: Record<string, string> = { logout_request: 'CfDJ8sealed_value-1' },
) {
  const navigation = fakeNavigation();
  TestBed.configureTestingModule({
    providers: [
      routeWith(query),
      { provide: SessionApi, useValue: api },
      { provide: BrowserNavigation, useValue: navigation },
    ],
  });
  const fixture = TestBed.createComponent(LogoutPage);
  await fixture.whenStable();
  return { fixture, root: fixture.nativeElement as HTMLElement, navigation };
}

function signOutButton(root: HTMLElement): HTMLButtonElement {
  return Array.from(root.querySelectorAll('button')).find(
    (b) => b.textContent?.trim() === 'Sign out',
  )!;
}

describe('LogoutPage', () => {
  it('asks first and ends nothing on load', async () => {
    const logout = vi.fn();
    const { root } = await render({ logout });

    expect(root.querySelector('h1')?.textContent).toBe('Sign out of Heimdall?');
    expect(text(root)).toContain('To stay signed in, close this tab.');
    expect(logout).not.toHaveBeenCalled();
  });

  it('sends back only the sealed value, then goes where Heimdall says', async () => {
    const logout = vi
      .fn()
      .mockResolvedValue({ redirect_to: 'https://app.example.com/bye?state=s1' });
    const { fixture, root, navigation } = await render({ logout });

    signOutButton(root).click();
    await fixture.whenStable();

    expect(logout).toHaveBeenCalledWith('CfDJ8sealed_value-1');
    expect(navigation.assign).toHaveBeenCalledWith('https://app.example.com/bye?state=s1');
  });

  it('sends no value when the address has none or a malformed one', async () => {
    const logout = vi.fn().mockResolvedValue({ redirect_to: '/account/signed-out?logout=done' });
    const { fixture, root, navigation } = await render(
      { logout },
      { logout_request: 'https://evil.example.com/' },
    );

    signOutButton(root).click();
    await fixture.whenStable();

    expect(logout).toHaveBeenCalledWith(null);
    expect(navigation.assign).toHaveBeenCalledWith('/account/signed-out?logout=done');
  });

  it('never follows a script address', async () => {
    const logout = vi.fn().mockResolvedValue({ redirect_to: 'javascript:alert(1)' });
    const { fixture, root, navigation } = await render({ logout });

    signOutButton(root).click();
    await fixture.whenStable();

    expect(navigation.assign).toHaveBeenCalledWith('/account/signed-out');
  });

  it('shows a problem and stays when the call fails', async () => {
    const logout = vi.fn().mockRejectedValue(new SessionApiError(0, null, null));
    const { fixture, root, navigation } = await render({ logout });

    signOutButton(root).click();
    await fixture.whenStable();

    expect(text(root)).toContain('Heimdall did not sign you out.');
    expect(navigation.assign).not.toHaveBeenCalled();
    expect(signOutButton(root).getAttribute('aria-disabled')).toBe('false');
  });

  it('sends one request for a double click', async () => {
    let finish: (value: { redirect_to: string }) => void = () => undefined;
    const logout = vi.fn().mockReturnValue(new Promise((resolve) => (finish = resolve)));
    const { fixture, root } = await render({ logout });

    signOutButton(root).click();
    signOutButton(root).click();
    finish({ redirect_to: '/account/signed-out?logout=done' });
    await fixture.whenStable();

    expect(logout).toHaveBeenCalledTimes(1);
  });
});
