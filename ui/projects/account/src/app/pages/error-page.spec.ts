import { TestBed } from '@angular/core/testing';
import { BrowserNavigation } from '../session/flow';
import { fakeNavigation, routeWith, text } from '../testing';
import { ErrorPage, knownCode } from './error-page';

async function render(error: string) {
  TestBed.configureTestingModule({
    providers: [routeWith({ error }), { provide: BrowserNavigation, useValue: fakeNavigation() }],
  });
  const fixture = TestBed.createComponent(ErrorPage);
  await fixture.whenStable();
  return fixture.nativeElement as HTMLElement;
}

describe('ErrorPage', () => {
  it('shows the text and the code for a known code', async () => {
    const root = await render('invalid_client');

    expect(text(root)).toContain('Heimdall does not know this app');
    expect(text(root)).toContain('Error code: invalid_client');
  });

  it('never prints a value outside the fixed list', async () => {
    const root = await render('Your account is locked. Call +1 555 0100');

    expect(text(root)).toContain('This sign-in cannot continue');
    expect(text(root)).not.toContain('555');
    expect(text(root)).not.toContain('Error code');
  });

  it('does not treat inherited object keys as codes', () => {
    expect(knownCode('constructor')).toBeNull();
    expect(knownCode('__proto__')).toBeNull();
  });
});
