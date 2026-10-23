import { Component, computed, input } from '@angular/core';

/** Authored icons on a 24px grid, one stroke weight (1.75), square caps to match the controls. */
const PATHS = {
  arrow: ['M4 12h15', 'M13 6l6 6-6 6'],
  alert: ['M12 3.5 2.5 20h19z', 'M12 10v4.5', 'M12 17.2v.3'],
  id: ['M3 5.5h18v13H3z', 'M6.5 10h4v4h-4z', 'M13.5 10.5h4', 'M13.5 13.5h3'],
  person: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M4.5 20.5c1-4 4-6 7.5-6s6.5 2 7.5 6'],
  mail: ['M3 5.5h18v13H3z', 'M3.5 6.5 12 13l8.5-6.5'],
  home: ['M3.5 11 12 4l8.5 7', 'M6 9.5v10h12v-10', 'M10 19.5v-5h4v5'],
  phone: ['M7 2.5h10v19H7z', 'M11 18h2'],
  offline: ['M19.5 12a7.5 7.5 0 1 1-2.2-5.3', 'M19.5 4v4h-4'],
  eye: ['M2.5 12Q12 3.5 21.5 12Q12 20.5 2.5 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'],
  'eye-off': [
    'M2.5 12Q12 3.5 21.5 12Q12 20.5 2.5 12z',
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    'M4 20 20 4',
  ],
  key: ['M8 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z', 'M11.5 12h9', 'M17.5 12v3', 'M20.5 12v2'],
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
