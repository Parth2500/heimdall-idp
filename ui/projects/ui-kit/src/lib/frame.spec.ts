import { TestBed } from '@angular/core/testing';
import { HdFrame } from './frame';

describe('HdFrame', () => {
  it('names the host on the plate and marks the main area busy', async () => {
    const fixture = TestBed.createComponent(HdFrame);
    fixture.componentRef.setInput('plateLabel', 'Signing in to');
    fixture.componentRef.setInput('host', 'acme.localhost:7200');
    fixture.componentRef.setInput('busy', true);
    await fixture.whenStable();

    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.plate')?.textContent).toContain('acme.localhost:7200');
    expect(root.querySelector('main')?.getAttribute('aria-busy')).toBe('true');
    expect(root.querySelector('.busy')).not.toBeNull();
  });

  it('uses the client tone for a client app', async () => {
    const fixture = TestBed.createComponent(HdFrame);
    fixture.componentRef.setInput('plateLabel', 'Client app on');
    fixture.componentRef.setInput('host', 'demo.localhost:4300');
    fixture.componentRef.setInput('tone', 'client');
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).classList).toContain('client');
  });

  it("carries the eye on Heimdall's band and never on a client's", async () => {
    const issuer = TestBed.createComponent(HdFrame);
    issuer.componentRef.setInput('plateLabel', 'Signing in to');
    issuer.componentRef.setInput('host', 'acme.localhost:7200');
    await issuer.whenStable();
    const eye = (issuer.nativeElement as HTMLElement).querySelector('.band svg.eye');
    expect(eye).not.toBeNull();
    expect(eye?.getAttribute('aria-hidden')).toBe('true');

    const client = TestBed.createComponent(HdFrame);
    client.componentRef.setInput('plateLabel', 'Client app on');
    client.componentRef.setInput('host', 'demo.localhost:4300');
    client.componentRef.setInput('tone', 'client');
    await client.whenStable();
    expect((client.nativeElement as HTMLElement).querySelector('.eye')).toBeNull();
  });
});
