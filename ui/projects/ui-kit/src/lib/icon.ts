import { Component, computed, input } from '@angular/core';

/** Authored icons on a 24px grid, one stroke weight (1.75), square caps to match the controls. */
const PATHS = {
  alert: ['M12 3.5 2.5 20h19z', 'M12 10v4.5', 'M12 17.2v.3'],
  eye: ['M2.5 12Q12 3.5 21.5 12Q12 20.5 2.5 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'],
  'eye-off': [
    'M2.5 12Q12 3.5 21.5 12Q12 20.5 2.5 12z',
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    'M4 20 20 4',
  ],
} as const;

export type IconName = keyof typeof PATHS;

@Component({
  selector: 'hd-icon',
  host: { 'aria-hidden': 'true' },
  template: `
    <svg viewBox="0 0 24 24" focusable="false">
      @for (d of paths(); track $index) {
        <path [attr.d]="d" />
      }
    </svg>
  `,
  styles: `
    :host {
      display: inline-block;
      width: 1.375rem;
      height: 1.375rem;
      flex: none;
    }

    svg {
      display: block;
      width: 100%;
      height: 100%;
      fill: none;
      stroke: currentColor;
      stroke-width: 1.75;
      stroke-linecap: square;
      stroke-linejoin: miter;
    }
  `,
})
export class HdIcon {
  readonly name = input.required<IconName>();
  protected readonly paths = computed(() => PATHS[this.name()]);
}
