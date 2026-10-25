import { TestBed } from '@angular/core/testing';
import { BrowserNavigation } from '../session/flow';
import { fakeNavigation, routeWith, text } from '../testing';
import { SignedOutPage } from './signed-out-page';

async function render(query: Record<string, string>) {
  TestBed.configureTestingModule({
    providers: [routeWith(query), { provide: BrowserNavigation, useValue: fakeNavigation() }],
  });
  const fixture = TestBed.createComponent(SignedOutPage);
  await fixture.whenStable();
  return fixture.nativeElement as HTMLElement;
}

describe('SignedOutPage', () => {
  it('confirms a sign-out that just ran', async () => {
    const root = await render({ logout: 'done' });

    expect(root.querySelector('h1')?.textContent).toBe('You are signed out');
    expect(text(root)).toContain('The next sign-in asks for your password.');
  });

  it('says only that no sign-in is in progress without the marker', async () => {
    const root = await render({});

    expect(root.querySelector('h1')?.textContent).toBe('No sign-in in progress');
  });

  it('shows no text from the address', async () => {
    const root = await render({ logout: 'You were hacked. Call +1 555 0100' });

    expect(text(root)).not.toContain('555');
    expect(root.querySelector('h1')?.textContent).toBe('No sign-in in progress');
  });
});
