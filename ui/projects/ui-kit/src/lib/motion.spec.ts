import { TestBed } from '@angular/core/testing';
import { HdMotion, HdMotionSwitch, MOTION_KEY } from './motion';

// jsdom has no matchMedia, so each test states what the system asks for.
function reducedMotion(reduce: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: reduce && query.includes('reduce'),
  }));
}

describe('HdMotion', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('follows prefers-reduced-motion when the viewer made no choice', () => {
    reducedMotion(true);
    expect(TestBed.inject(HdMotion).on()).toBe(false);
  });

  it('moves by default when the system does not ask for less motion', () => {
    reducedMotion(false);
    expect(TestBed.inject(HdMotion).on()).toBe(true);
  });

  it('keeps the choice of the switch over the system default', () => {
    reducedMotion(true);
    localStorage.setItem(MOTION_KEY, 'on');
    expect(TestBed.inject(HdMotion).on()).toBe(true);
  });

  it('still works when storage throws', () => {
    reducedMotion(false);
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const motion = TestBed.inject(HdMotion);

    motion.toggle();

    expect(motion.on()).toBe(false);
  });
});

describe('HdMotionSwitch', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('is a toggle button that stops the scene and remembers it', async () => {
    reducedMotion(false);
    const fixture = TestBed.createComponent(HdMotionSwitch);
    await fixture.whenStable();
    const button = (fixture.nativeElement as HTMLElement).querySelector('button')!;
    expect(button.getAttribute('aria-pressed')).toBe('true');

    button.click();
    await fixture.whenStable();

    expect(button.getAttribute('aria-pressed')).toBe('false');
    expect(button.textContent?.trim()).toBe('Motion');
    expect(localStorage.getItem(MOTION_KEY)).toBe('off');
    expect(document.documentElement.dataset['motion']).toBe('off');
  });
});
