import { TestBed } from '@angular/core/testing';
import { BrowserNavigation } from '../session/flow';
import { fakeNavigation, routeWith, text } from '../testing';
import { ErrorPage, dropLetters, knownCode } from './error-page';

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
    expect(root.querySelector('dt')?.textContent).toBe('Error code');
    expect(root.querySelector('dd code')?.textContent).toBe('invalid_client');
    expect(root.querySelector('h1')?.textContent).toBe('Heimdall does not know this app');
    expect(root.querySelector('hd-gate')?.getAttribute('data-bridge')).toBe('refused');
  });

  it('shows no guard fire when Heimdall is only busy', async () => {
    const root = await render('temporarily_unavailable');

    expect(root.querySelector('h1')?.textContent).toBe('Heimdall is busy');
    expect(root.querySelector('hd-gate')?.getAttribute('data-bridge')).toBe('idle');
  });

  it('never prints a value outside the fixed list', async () => {
    const root = await render('Your account is locked. Call +1 555 0100');

    expect(text(root)).toContain('This sign-in cannot continue');
    expect(text(root)).not.toContain('555');
    expect(text(root)).not.toContain('Error code');
  });

  it('splits the statement into letters 40ms apart and keeps words whole', () => {
    const words = dropLetters('Gate shut');

    expect(words.map((w) => w.letters.map((l) => l.char).join(''))).toEqual(['Gate', 'shut']);
    expect(words[1].letters[0].delay).toBe(160);
  });

  it('does not treat inherited object keys as codes', () => {
    expect(knownCode('constructor')).toBeNull();
    expect(knownCode('__proto__')).toBeNull();
  });
});
