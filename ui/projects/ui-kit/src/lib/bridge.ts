import { Component, inject, input } from '@angular/core';
import { HdMotion } from './motion';

/**
 * The state of the crossing. The bridge shows it, and the page also says it in words.
 *   idle      the gate is open; nothing is in progress
 *   busy      Heimdall is checking something
 *   refused   Heimdall or the user refused; guard fire burns
 *   crossing  the check passed; the browser leaves for the app
 */
export type BridgeState = 'idle' | 'busy' | 'refused' | 'crossing';

/** The box of the arc: the circle's center is the bottom-right corner of the box. */
const BOX = 1150;

interface Band {
  readonly radius: number;
  readonly width: number;
  readonly tone: string;
}

/** Frost bands, from the outside in. Each gap between bands shows the sky. */
const FROST: readonly Band[] = [
  { radius: 1046, width: 36, tone: 'var(--hd-bridge-1)' },
  { radius: 1002, width: 44, tone: 'var(--hd-bridge-2)' },
  { radius: 952, width: 48, tone: 'var(--hd-bridge-3)' },
  { radius: 900, width: 48, tone: 'var(--hd-bridge-4)' },
];

const GUARD_RADIUS = 1092;
const EMBER_RADIUS = 1074;

/** A quarter circle from the ground (left end) up to the sky (top end). */
function arc(radius: number): string {
  return `M ${BOX - radius} ${BOX} A ${radius} ${radius} 0 0 1 ${BOX} ${BOX - radius}`;
}

interface Star {
  readonly x: number;
  readonly y: number;
  readonly r: number;
}

/** A fixed sky: the same stars on every load, from a small deterministic generator. */
function sky(count: number): Star[] {
  let seed = 0x9e3779b9;
  const next = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
  return Array.from({ length: count }, () => ({
    x: Math.round(next() * 1600),
    // Below the header line, so no star sits on the wordmark or the switch.
    y: 130 + Math.round(next() * 490),
    r: 0.7 + Math.round(next() * 10) / 10,
  }));
}

/**
 * Bifröst behind the gate: a sky of stars and the arc of the bridge. It is decoration with a
 * job: it shows the state of the crossing. It is hidden from assistive technology, because the
 * page says the same state in text.
 */
@Component({
  selector: 'hd-bridge',
  host: { 'aria-hidden': 'true', '[attr.data-state]': 'state()', '[class.still]': '!motion.on()' },
  template: `
    <svg class="sky" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMin slice" focusable="false">
      @for (star of stars; track $index) {
        <circle class="star" [attr.cx]="star.x" [attr.cy]="star.y" [attr.r]="star.r" />
      }
    </svg>
    <svg class="arc" [attr.viewBox]="viewBox" focusable="false">
      <defs>
        <filter id="hd-bridge-soft" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="10" />
        </filter>
        <filter id="hd-bridge-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="22" />
        </filter>
        <!-- The lights stay on the bands: soft along the arc, never spilling into the gaps. -->
        <mask
          id="hd-bridge-bands"
          maskUnits="userSpaceOnUse"
          x="0"
          y="0"
          [attr.width]="box"
          [attr.height]="box"
        >
          @for (band of frost; track band.radius) {
            <path [attr.d]="band.d" [attr.stroke-width]="band.width" stroke="#fff" fill="none" />
          }
        </mask>
      </defs>
      <!-- The fire's glow sits under the bands, so the frost stays crisp beside the flame. -->
      <path class="glow" [attr.d]="guard" stroke-width="90" filter="url(#hd-bridge-glow)" />
      @for (band of frost; track band.radius) {
        <path
          class="band"
          [attr.d]="band.d"
          [attr.stroke]="band.tone"
          [attr.stroke-width]="band.width"
        />
      }
      <g class="lights" mask="url(#hd-bridge-bands)">
        <g filter="url(#hd-bridge-soft)">
          @for (band of frost; track band.radius) {
            <path
              class="light"
              [attr.d]="band.d"
              [attr.stroke-width]="band.width"
              pathLength="100"
            />
          }
        </g>
      </g>
      <path class="ember" [attr.d]="ember" stroke-width="3" />
      <path class="guard" [attr.d]="guard" />
    </svg>
  `,
  styles: `
    :host {
      display: block;
      position: absolute;
      inset: 0;
      overflow: hidden;
      pointer-events: none;
    }

    svg {
      position: absolute;
      display: block;
      overflow: visible;
    }

    /* The stars stay in the first screen of sky, so they never speckle the text below it. */
    .sky {
      inset: 0 0 auto;
      width: 100%;
      height: min(100%, 100vh, 40rem);
    }

    .star {
      fill: var(--hd-star);
      animation: twinkle 5.2s ease-in-out infinite;
    }
    .star:nth-child(2n) {
      animation-duration: 7.4s;
      animation-delay: -2.1s;
    }
    .star:nth-child(3n) {
      animation-duration: 4.1s;
      animation-delay: -3.3s;
    }
    .star:nth-child(5n) {
      animation-duration: 8.8s;
      animation-delay: -0.7s;
    }
    .star:nth-child(7n) {
      animation-name: none;
      opacity: 0.45;
    }

    @keyframes twinkle {
      0%,
      100% {
        opacity: 0.9;
      }
      50% {
        opacity: 0.25;
      }
    }

    /* The arc's box is placed by the frame (--hd-bridge-*), so each layout picks its own view. */
    .arc {
      width: var(--hd-bridge-size, 72rem);
      height: var(--hd-bridge-size, 72rem);
      right: var(--hd-bridge-right, -14rem);
      bottom: var(--hd-bridge-bottom, -22rem);
      top: var(--hd-bridge-top, auto);
      transform: var(--hd-bridge-transform, none);
    }

    path {
      fill: none;
    }

    .band {
      transition: filter 600ms var(--hd-ease-out);
    }

    .ember {
      stroke: var(--hd-ember-bright);
      transition: stroke 400ms var(--hd-ease-out);
    }

    .guard {
      stroke: var(--hd-ember-banked);
      stroke-width: 16px;
      transition:
        stroke 400ms var(--hd-ease-out),
        stroke-width 700ms var(--hd-ease-out);
    }

    .glow {
      stroke: var(--hd-fire);
      opacity: 0;
      transition: opacity 500ms var(--hd-ease-out);
    }

    /* At night the lights add to the band color, like light, not paint over it. */
    @media (prefers-color-scheme: dark) {
      .lights {
        mix-blend-mode: plus-lighter;
      }
    }

    /* Lights travel up the bands, from the gate on the ground toward the sky. */
    .light {
      stroke: var(--hd-bridge-light);
      stroke-dasharray: 12 88;
      stroke-dashoffset: 12;
      opacity: 0.26;
      animation: run 13s linear infinite;
    }
    .light:nth-child(2) {
      animation-duration: 16s;
      animation-delay: -6s;
    }
    .light:nth-child(3) {
      animation-duration: 11s;
      animation-delay: -3s;
    }
    .light:nth-child(4) {
      animation-duration: 19s;
      animation-delay: -12s;
    }

    @keyframes run {
      from {
        stroke-dashoffset: 12;
      }
      to {
        stroke-dashoffset: -100;
      }
    }

    /* Busy: Heimdall checks. A stream of lights runs up every band, so the visible part of the
       arc always carries one, whatever the panel covers. */
    :host([data-state='busy']) .light {
      opacity: 0.7;
      stroke-dasharray: 9 24;
      animation: flow 0.8s linear infinite;
    }
    :host([data-state='busy']) .light:nth-child(2) {
      animation-delay: -0.1s;
    }
    :host([data-state='busy']) .light:nth-child(3) {
      animation-delay: -0.2s;
    }
    :host([data-state='busy']) .light:nth-child(4) {
      animation-delay: -0.3s;
    }

    @keyframes flow {
      from {
        stroke-dashoffset: 0;
      }
      to {
        stroke-dashoffset: -33;
      }
    }

    /* Crossing: the whole bridge lights from the gate to the sky, once. */
    :host([data-state='crossing']) .light {
      opacity: 0.55;
      stroke-dasharray: 100 100;
      animation: cross 700ms var(--hd-ease-out) forwards;
    }
    :host([data-state='crossing']) .light:nth-child(2) {
      animation-delay: 60ms;
    }
    :host([data-state='crossing']) .light:nth-child(3) {
      animation-delay: 120ms;
    }
    :host([data-state='crossing']) .light:nth-child(4) {
      animation-delay: 180ms;
    }

    @keyframes cross {
      from {
        stroke-dashoffset: 100;
      }
      to {
        stroke-dashoffset: 0;
      }
    }

    /* Refused: the guard fire flares, the frost dims, and no light crosses. */
    :host([data-state='refused']) .guard {
      stroke: var(--hd-fire);
      stroke-width: 44px;
    }
    :host([data-state='refused']) .ember {
      stroke: var(--hd-fire);
    }
    :host([data-state='refused']) .glow {
      opacity: 0.5;
      animation: burn 2.4s ease-in-out infinite;
    }
    /* Dim the frost by darkening it at full opacity, so no fire shows through a band. */
    :host([data-state='refused']) .band {
      filter: brightness(0.55);
    }
    :host([data-state='refused']) .light {
      opacity: 0;
      animation: none;
    }

    @keyframes burn {
      0%,
      100% {
        opacity: 0.42;
      }
      30% {
        opacity: 0.62;
      }
      55% {
        opacity: 0.36;
      }
      80% {
        opacity: 0.56;
      }
    }

    /* Motion off (the switch, or prefers-reduced-motion by default): the scene holds still.
       The state stays visible: crossing lights the whole bridge, refused keeps the fire. */
    :host(.still) * {
      animation: none !important;
      transition: none !important;
    }
    :host(.still) .light {
      opacity: 0;
    }
    :host(.still[data-state='crossing']) .light {
      opacity: 0.55;
      stroke-dashoffset: 0;
    }

    @media (forced-colors: active) {
      :host {
        display: none;
      }
    }
  `,
})
export class HdBridge {
  protected readonly motion = inject(HdMotion);
  readonly state = input<BridgeState>('idle');

  protected readonly box = BOX;
  protected readonly viewBox = `0 0 ${BOX} ${BOX}`;
  protected readonly frost = FROST.map((band) => ({ ...band, d: arc(band.radius) }));
  protected readonly ember = arc(EMBER_RADIUS);
  protected readonly guard = arc(GUARD_RADIUS);
  protected readonly stars = sky(46);
}
