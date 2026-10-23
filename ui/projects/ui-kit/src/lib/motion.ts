import { Component, DOCUMENT, Injectable, effect, inject, signal } from '@angular/core';

/** The key of the viewer's motion choice. It is a convenience for one browser, not a setting. */
export const MOTION_KEY = 'heimdall.motion';

/**
 * Whether the bridge scene moves. The default follows `prefers-reduced-motion`. A choice on the
 * switch wins over the default and stays in this browser. Storage can fail (private windows,
 * blocked site data), so every read and write is guarded and the page works without it.
 */
@Injectable({ providedIn: 'root' })
export class HdMotion {
  private readonly document = inject(DOCUMENT);
  private readonly window = this.document.defaultView;

  readonly on = signal(this.initial());

  constructor() {
    effect(() => {
      this.document.documentElement.dataset['motion'] = this.on() ? 'on' : 'off';
    });
  }

  toggle(): void {
    const next = !this.on();
    this.on.set(next);
    try {
      this.window?.localStorage.setItem(MOTION_KEY, next ? 'on' : 'off');
    } catch {
      // The choice lasts for this page only.
    }
  }

  private initial(): boolean {
    try {
      const saved = this.window?.localStorage.getItem(MOTION_KEY);
      if (saved === 'on' || saved === 'off') {
        return saved === 'on';
      }
    } catch {
      // No stored choice.
    }
    return !(this.window?.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false);
  }
}

/** The switch that starts and stops the bridge scene. A toggle button: `aria-pressed` is the state. */
@Component({
  selector: 'hd-motion-switch',
  template: `
    <button
      type="button"
      class="switch"
      [attr.aria-pressed]="motion.on()"
      (click)="motion.toggle()"
    >
      <span class="track" aria-hidden="true"><span class="knob"></span></span>
      Motion
    </button>
  `,
  styles: `
    .switch {
      display: inline-flex;
      align-items: center;
      gap: var(--hd-2);
      min-height: 2.75rem;
      padding: 0 var(--hd-3);
      border: 1px solid transparent;
      border-radius: 0;
      background: transparent;
      color: var(--hd-ink-muted);
      font: inherit;
      font-size: var(--hd-text-s);
      font-weight: 600;
      cursor: pointer;
    }

    .switch:hover {
      color: var(--hd-ink);
      border-color: var(--hd-line);
    }

    .track {
      position: relative;
      width: 2rem;
      height: 1rem;
      border: 1px solid currentColor;
    }

    .knob {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 0.625rem;
      height: 0.625rem;
      background: currentColor;
      transition: transform 200ms var(--hd-ease-out);
    }

    [aria-pressed='true'] .track {
      border-color: var(--hd-act);
      background: var(--hd-act);
    }

    [aria-pressed='true'] .knob {
      background: var(--hd-on-act);
      transform: translateX(1rem);
    }

    @media (forced-colors: active) {
      [aria-pressed='true'] .track {
        background: Highlight;
      }
    }
  `,
})
export class HdMotionSwitch {
  protected readonly motion = inject(HdMotion);
}
