import { TestBed } from '@angular/core/testing';
import { SessionApi, SessionApiError } from '../session/session-api';
import { BrowserNavigation } from '../session/flow';
import { REQUEST_ID, fakeNavigation, routeWith, text } from '../testing';
import { LoginPage, isRefusal, messageFor } from './login-page';

async function render(query: Record<string, string>, login = vi.fn()) {
  const navigation = fakeNavigation();
  TestBed.configureTestingModule({
    providers: [
      routeWith(query),
      { provide: SessionApi, useValue: { login } },
      { provide: BrowserNavigation, useValue: navigation },
    ],
  });
  const fixture = TestBed.createComponent(LoginPage);
  await fixture.whenStable();
  return { fixture, root: fixture.nativeElement as HTMLElement, navigation, login };
}

async function fill(root: HTMLElement, email: string, password: string) {
  for (const [id, value] of [
    ['email', email],
    ['password', password],
  ]) {
    const input = root.querySelector<HTMLInputElement>(`#${id}`)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }
}

describe('LoginPage', () => {
  it('shows no form without a valid request_id', async () => {
    const { root } = await render({ request_id: 'https://evil.example' });

    expect(root.querySelector('form')).toBeNull();
    expect(text(root)).toContain('No sign-in in progress');
  });

  it('shows the host and the address bar check', async () => {
    const { root } = await render({ request_id: REQUEST_ID });

    const host = root.querySelector('.host')!;
    expect(host.textContent).toContain('You are on');
    expect(host.querySelector('.host__name')?.textContent).toBe('acme.localhost:7200');
    expect(host.textContent).toContain('Check that your address bar shows the same host.');
  });

  it('shows the password with an eye toggle inside the field', async () => {
    const { fixture, root } = await render({ request_id: REQUEST_ID });
    const toggle = root.querySelector<HTMLButtonElement>('.hd-input-toggle')!;
    expect(toggle.getAttribute('aria-label')).toBe('Show password');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');

    toggle.click();
    await fixture.whenStable();

    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(root.querySelector('#password')?.getAttribute('type')).toBe('text');
  });

  it('names the action Sign in, in the heading and on the button', async () => {
    const { root } = await render({ request_id: REQUEST_ID });

    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Sign in');
    expect(root.querySelector('button[type=submit]')?.textContent?.trim()).toBe('Sign in');
  });

  it('asks for the email first when the form is empty', async () => {
    const { fixture, root, login } = await render({ request_id: REQUEST_ID });

    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();

    expect(login).not.toHaveBeenCalled();
    expect(root.querySelector('[role=alert]')?.textContent).toContain('Enter your email address.');
    expect(root.querySelector('#email')?.getAttribute('aria-invalid')).toBe('true');
    // A missing field is not a refusal: Heimdall did not answer anything yet.
    expect(root.querySelector('hd-card')?.getAttribute('data-state')).toBe('idle');
  });

  it('sends the browser only to the resume path after sign-in', async () => {
    const { fixture, root, navigation, login } = await render(
      { request_id: REQUEST_ID, return_to: 'https://evil.example' },
      vi.fn().mockResolvedValue(undefined),
    );
    await fill(root, ' alice@acme.localhost ', 'correct horse');

    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();

    expect(login).toHaveBeenCalledWith('alice@acme.localhost', 'correct horse');
    expect(navigation.assign).toHaveBeenCalledWith(
      `/oauth/v1/authorize/resume?request_id=${REQUEST_ID}`,
    );
    expect(root.querySelector('hd-card')?.getAttribute('data-state')).toBe('crossing');
  });

  it('shows one generic text for wrong credentials and clears the password', async () => {
    const { fixture, root } = await render(
      { request_id: REQUEST_ID },
      vi.fn().mockRejectedValue(new SessionApiError(401, 'invalid_credentials', null)),
    );
    await fill(root, 'alice@acme.localhost', 'wrong');

    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();

    expect(root.querySelector('[role=alert]')?.textContent).toContain(
      'The email or the password is not correct.',
    );
    expect(root.querySelector<HTMLInputElement>('#password')!.value).toBe('');
    expect(root.querySelector('hd-card')?.getAttribute('data-state')).toBe('refused');
  });

  it('shows no guard fire when Heimdall did not answer', async () => {
    const { fixture, root } = await render(
      { request_id: REQUEST_ID },
      vi.fn().mockRejectedValue(new SessionApiError(0, null, null)),
    );
    await fill(root, 'alice@acme.localhost', 'secret');

    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();

    expect(root.querySelector('[role=alert]')).not.toBeNull();
    expect(root.querySelector('hd-card')?.getAttribute('data-state')).toBe('idle');
  });
});

describe('isRefusal', () => {
  it('is true only for wrong credentials and the throttle', () => {
    expect(isRefusal(new SessionApiError(401, null, null))).toBe(true);
    expect(isRefusal(new SessionApiError(429, null, 30))).toBe(true);
    expect(isRefusal(new SessionApiError(503, null, null))).toBe(false);
    expect(isRefusal(new SessionApiError(0, null, null))).toBe(false);
    expect(isRefusal(new Error('network'))).toBe(false);
  });
});

describe('messageFor', () => {
  it('names the wait from Retry-After and never says locked', () => {
    const message = messageFor(new SessionApiError(429, null, 30));

    expect(message).toBe('Too many attempts from this network. Try again in 30 seconds.');
    expect(message.toLowerCase()).not.toContain('lock');
  });

  it('has a text for a busy server and for no answer', () => {
    expect(messageFor(new SessionApiError(503, 'temporarily_unavailable', null))).toContain('busy');
    expect(messageFor(new Error('offline'))).toContain('did not answer');
  });
});
