import { Component, inject, input } from '@angular/core';
import { BridgeState, HdBridge } from './bridge';
import { HdMotion, HdMotionSwitch } from './motion';

/**
 * The frame of every Heimdall account page: the gate at the foot of the bridge (U15).
 *
 * The page puts its statement (the h1) in `[hdStatement]` and its task in the default slot, which
 * becomes the gatehouse panel. The gate plaque names the host that the browser is on. The host is
 * already in the address bar, so the plaque reveals nothing new. It helps the user compare the two
 * and see a phishing copy.
 */
@Component({
  selector: 'hd-gate',
  imports: [HdBridge, HdMotionSwitch],
  host: { '[attr.data-bridge]': 'bridge()', '[class.still]': '!motion.on()' },
  template: `
    <hd-bridge class="bridge" [state]="bridge()" [lit]="lit()" />

    <header class="brand">
      <!-- The watcher's eye (docs/brand). Only Heimdall's own pages carry it: a client is not Heimdall. -->
      <svg class="eye" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
        <path
          fill-rule="evenodd"
          d="M7 32Q32 8 57 32Q32 56 7 32z M41.5 32a9.5 9.5 0 1 0-19 0a9.5 9.5 0 1 0 19 0z"
        />
        <circle cx="32" cy="29.5" r="3.2" />
        <path d="M30.5 31 29.2 38.5h5.6L33.5 31z" />
      </svg>
      <span class="wordmark">Heimdall</span>
    </header>

    <main id="main" class="main" [attr.aria-busy]="bridge() === 'busy'">
      <div class="statement"><ng-content select="[hdStatement]" /></div>

      <p class="plaque">
        <span class="plaque__label">{{ plateLabel() }}</span>
        <span class="plaque__host">{{ host() }}</span>
        <span class="plaque__check">Check that your address bar shows the same host.</span>
      </p>

      <div class="panel">
        <ng-content />
        <p class="hd-note">
          Heimdall identity provider. Development build, not for production use.
        </p>
      </div>
    </main>

    <div class="motion"><hd-motion-switch /></div>
  `,
  styles: `
    :host {
      position: relative;
      display: grid;
      min-height: 100vh;
      min-height: 100dvh;
      padding: var(--hd-6) var(--hd-4) var(--hd-6);
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas:
        'brand'
        'motion'
        'main';
      grid-template-rows: auto auto 1fr;
      overflow: hidden;
      isolation: isolate;

      /* Phone: the bridge is a corner arc, seen from below. */
      --hd-bridge-size: 30rem;
      --hd-bridge-right: -14rem;
      --hd-bridge-top: -13rem;
      --hd-bridge-bottom: auto;
      --hd-bridge-transform: scaleY(-1);
    }

    .bridge {
      z-index: -1;
    }

    .brand {
      grid-area: brand;
      display: flex;
      align-items: center;
      gap: var(--hd-3);
      color: var(--hd-display);
    }

    .eye {
      flex: none;
      width: 2rem;
      height: 2rem;
      fill: currentColor;
    }

    .wordmark {
      font-size: var(--hd-text-l);
      font-weight: 800;
      letter-spacing: -0.02em;
      line-height: 1;
    }

    .main {
      grid-area: main;
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      align-content: start;
      gap: var(--hd-5);
      padding-top: var(--hd-4);
    }

    .statement {
      --hd-display-size: clamp(3.5rem, 1.5rem + 9vw, 10rem);
    }

    .plaque {
      display: grid;
      gap: var(--hd-1);
    }

    .plaque__label {
      color: var(--hd-ink-muted);
      font-size: var(--hd-text-xs);
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }

    .plaque__host {
      font-family: var(--hd-mono);
      font-size: var(--hd-text-host);
      font-weight: 700;
      line-height: 1.2;
      overflow-wrap: anywhere;
    }

    .plaque__check {
      color: var(--hd-ink-muted);
      font-size: var(--hd-text-s);
    }

    .panel {
      display: grid;
      gap: var(--hd-6);
      align-content: start;
    }

    /* Tablet: the phone order, in a column that keeps a reading measure. */
    @media (min-width: 40rem) {
      .main {
        max-width: 34rem;
      }

      :host {
        --hd-bridge-size: 40rem;
        --hd-bridge-right: -12rem;
        --hd-bridge-top: -17rem;
      }
    }

    /* The switch is in the first screen on every layout. On a phone it sits under the wordmark,
       in the clear sky left of the arc. */
    .motion {
      grid-area: motion;
      justify-self: start;
      margin: var(--hd-1) 0 0 calc(-1 * var(--hd-3));
    }

    /* Desktop: the statement on the left, the gatehouse on the right, the plaque at the foot. */
    @media (min-width: 64rem) {
      :host {
        padding: var(--hd-8) var(--hd-12) var(--hd-10);
        grid-template-columns: minmax(0, 1fr) auto;
        grid-template-areas:
          'brand motion'
          'main main';
        grid-template-rows: auto 1fr;

        --hd-scene: min(100vw, 142vh);
        --hd-bridge-size: calc(var(--hd-scene) * 0.9);
        --hd-bridge-right: calc(var(--hd-scene) * -0.172);
        --hd-bridge-bottom: calc(var(--hd-scene) * -0.273);
        --hd-bridge-top: auto;
        --hd-bridge-transform: none;
      }

      .motion {
        justify-self: end;
        margin: 0 calc(-1 * var(--hd-3)) 0 0;
      }

      .main {
        max-width: none;
        grid-template-columns: minmax(0, 1fr) var(--hd-panel-width);
        grid-template-rows: 1fr auto;
        grid-template-areas:
          'statement panel'
          'plaque panel';
        column-gap: var(--hd-10);
        row-gap: var(--hd-8);
        padding-top: var(--hd-6);
      }

      .statement {
        grid-area: statement;
        align-self: center;
        --hd-display-size: clamp(6rem, 1rem + 11vw, 11.5rem);
        /* About two words a line: the statement stacks like a sign at the gate. */
        --hd-display-measure: 3em;
      }

      .plaque {
        grid-area: plaque;
        align-self: end;
      }

      .panel {
        grid-area: panel;
        align-self: center;
        padding: var(--hd-8) var(--hd-8) var(--hd-6);
        border: 1px solid var(--hd-line);
        background: var(--hd-panel);
      }
    }

    /* The gate's fire follows the bridge: ember at rest, guard fire on a refusal. */
    :host([data-bridge='refused']) ::ng-deep .hd-display__fire {
      color: var(--hd-fire);
    }

    :host([data-bridge='refused']) .panel {
      border-color: var(--hd-fire);
    }

    /* A refused attempt shakes the panel once. Only an attempt shows a problem box, so the error
       page and a Deny do not shake. */
    :host([data-bridge='refused']:not(.still)) .panel:has(.hd-problem) {
      animation: shake 420ms var(--hd-ease-out);
    }

    @keyframes shake {
      20% {
        transform: translateX(-10px);
      }
      40% {
        transform: translateX(8px);
      }
      60% {
        transform: translateX(-6px);
      }
      80% {
        transform: translateX(3px);
      }
    }

    @media (forced-colors: active) {
      .panel {
        border: 2px solid CanvasText;
      }
    }
  `,
})
export class HdGate {
  protected readonly motion = inject(HdMotion);
  readonly plateLabel = input('You are at the gate of');
  readonly host = input.required<string>();
  readonly bridge = input<BridgeState>('idle');
  /** How far the crossing has come: the number of lit bands (0 to 4). */
  readonly lit = input(0);
}
