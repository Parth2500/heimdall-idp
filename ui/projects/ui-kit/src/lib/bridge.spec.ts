import { TestBed } from '@angular/core/testing';
import { HdBridge } from './bridge';
import { HdMotion } from './motion';

describe('HdBridge', () => {
  it('draws the same sky on every load', async () => {
    const a = TestBed.createComponent(HdBridge);
    await a.whenStable();
    const first = (a.nativeElement as HTMLElement).querySelector('.star')?.getAttribute('cx');

    const b = TestBed.createComponent(HdBridge);
    await b.whenStable();
    const second = (b.nativeElement as HTMLElement).querySelector('.star')?.getAttribute('cx');

    expect(first).toBe(second);
  });

  it('shows its state, and holds still when motion is off', async () => {
    const fixture = TestBed.createComponent(HdBridge);
    fixture.componentRef.setInput('state', 'refused');
    TestBed.inject(HdMotion).on.set(false);
    await fixture.whenStable();
    const host = fixture.nativeElement as HTMLElement;

    expect(host.getAttribute('data-state')).toBe('refused');
    expect(host.classList).toContain('still');
    expect(host.getAttribute('aria-hidden')).toBe('true');
  });

  it('lights bands from the ground up, all of them when crossing, and burns all on refusal', async () => {
    const fixture = TestBed.createComponent(HdBridge);
    fixture.componentRef.setInput('lit', 2);
    await fixture.whenStable();
    const host = fixture.nativeElement as HTMLElement;
    const lit = () =>
      Array.from(host.querySelectorAll('.band')).map((b) => b.classList.contains('lit'));

    // Bands are listed from the outside in, so the two inner bands light first.
    expect(lit()).toEqual([false, false, true, true]);

    fixture.componentRef.setInput('state', 'crossing');
    await fixture.whenStable();
    expect(lit()).toEqual([true, true, true, true]);
  });
});
