import { TestBed } from '@angular/core/testing';
import { ClientFrame } from './client-frame';

describe('ClientFrame', () => {
  it('names the host on the plate and marks the main area busy', async () => {
    const fixture = TestBed.createComponent(ClientFrame);
    fixture.componentRef.setInput('wordmark', 'Demo client');
    fixture.componentRef.setInput('plateLabel', 'A Heimdall client app on');
    fixture.componentRef.setInput('host', 'demo.localhost:4300');
    fixture.componentRef.setInput('busy', true);
    await fixture.whenStable();

    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.plate')?.textContent).toContain('demo.localhost:4300');
    expect(root.querySelector('main')?.getAttribute('aria-busy')).toBe('true');
    expect(root.querySelector('.busy')).not.toBeNull();
  });

  it("never carries Heimdall's eye: a client is not Heimdall", async () => {
    const fixture = TestBed.createComponent(ClientFrame);
    fixture.componentRef.setInput('wordmark', 'Demo client');
    fixture.componentRef.setInput('plateLabel', 'A Heimdall client app on');
    fixture.componentRef.setInput('host', 'demo.localhost:4300');
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).querySelector('svg')).toBeNull();
  });
});
