import { TestBed } from '@angular/core/testing';
import { HdGate } from './gate';

async function render(bridge: 'idle' | 'busy' | 'refused' | 'crossing' = 'idle') {
  const fixture = TestBed.createComponent(HdGate);
  fixture.componentRef.setInput('host', 'acme.localhost:7200');
  fixture.componentRef.setInput('bridge', bridge);
  await fixture.whenStable();
  return fixture.nativeElement as HTMLElement;
}

describe('HdGate', () => {
  it('names the host on the plaque and asks the user to compare it', async () => {
    const root = await render();

    expect(root.querySelector('.plaque__label')?.textContent).toBe('You are at the gate of');
    expect(root.querySelector('.plaque__host')?.textContent).toBe('acme.localhost:7200');
    expect(root.querySelector('.plaque')?.textContent).toContain(
      'Check that your address bar shows the same host.',
    );
  });

  it('passes the state to the bridge and marks the main area busy while Heimdall checks', async () => {
    const root = await render('busy');

    expect(root.getAttribute('data-bridge')).toBe('busy');
    expect(root.querySelector('hd-bridge')?.getAttribute('data-state')).toBe('busy');
    expect(root.querySelector('main')?.getAttribute('aria-busy')).toBe('true');
  });

  it("carries Heimdall's eye, hidden from assistive technology", async () => {
    const root = await render();

    expect(root.querySelector('header svg.eye')?.getAttribute('aria-hidden')).toBe('true');
    expect(root.querySelector('hd-bridge')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('always says it is a development build', async () => {
    const root = await render();

    expect(root.querySelector('.panel .hd-note')?.textContent).toContain(
      'Development build, not for production use.',
    );
  });
});
