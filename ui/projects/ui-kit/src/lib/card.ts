import { Component, input } from '@angular/core';

/** What the card shows about the request. Pages set it; the card never decides it. */
export type CardState = 'idle' | 'busy' | 'refused' | 'crossing';

/**
 * The frame of every Heimdall account page: one centered card (U16).
 *
 * The page puts its title (the h1) in `[hdStatement]` and its task in the default slot. The host
 * block names the host that the browser is on. The host is already in the address bar, so the
 * block reveals nothing new. It helps the user compare the two and see a phishing copy.
 */
@Component({
  selector: 'hd-card',
  host: { '[attr.data-state]': 'state()' },
  template: `
    <div class="page">
      <main id="main" class="card" [attr.aria-busy]="state() === 'busy'">
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

        <p class="host">
          <span class="hd-kicker">{{ hostLabel() }}</span>
          <span class="host__name">{{ host() }}</span>
          <span class="host__check">Check that your address bar shows the same host.</span>
        </p>

        <div class="statement"><ng-content select="[hdStatement]" /></div>

        <ng-content />
      </main>

      <footer class="foot">
        <span>Development build. Not for production use.</span>
        <span>Heimdall identity provider</span>
      </footer>
    </div>
  `,
  styles: `
    :host {
      display: block;
      min-height: 100vh;
      min-height: 100dvh;
      background-color: var(--hd-ground);
      /* A faint ledger grid, cleared behind the card. */
      background-image:
        radial-gradient(ellipse 34% 48% at 50% 50%, var(--hd-ground) 55%, transparent 100%),
        linear-gradient(var(--hd-grid-major) 1px, transparent 1px),
        linear-gradient(90deg, var(--hd-grid-major) 1px, transparent 1px),
        linear-gradient(var(--hd-grid-minor) 1px, transparent 1px),
        linear-gradient(90deg, var(--hd-grid-minor) 1px, transparent 1px);
      background-size:
        100% 100%,
        120px 120px,
        120px 120px,
        24px 24px,
        24px 24px;
      background-position: center;
    }

    .page {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: var(--hd-4);
      min-height: inherit;
      padding: 3rem var(--hd-6);
    }

    .card {
      display: flex;
      flex-direction: column;
      gap: var(--hd-6);
      width: 100%;
      max-width: var(--hd-card-width);
      padding: 2.25rem 2.5rem 2rem;
      border: 1px solid var(--hd-line);
      border-radius: var(--hd-radius-card);
      background: var(--hd-card);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.625rem;
      font-size: 1.125rem;
      font-weight: 700;
      letter-spacing: -0.01em;
    }

    .eye {
      flex: none;
      width: 1.75rem;
      height: 1.75rem;
      fill: currentColor;
    }

    .host {
      display: grid;
      gap: var(--hd-1);
      padding-top: var(--hd-3);
      border-top: 2px solid var(--hd-ink);
    }

    .host__name {
      font-family: var(--hd-mono);
      font-size: var(--hd-text-host);
      font-weight: 600;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }

    .host__check {
      color: var(--hd-ink-soft);
      font-size: var(--hd-text-s);
      line-height: 1.45;
    }

    .foot {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: var(--hd-2);
      width: 100%;
      max-width: var(--hd-card-width);
      color: var(--hd-ink-muted);
      font-size: var(--hd-text-xs);
    }

    /* Phone: the card loses its border and fills the screen. */
    @media (max-width: 32.5rem) {
      :host {
        background-image: none;
      }

      .page {
        justify-content: flex-start;
        padding: 0 0 var(--hd-6);
      }

      .card {
        border: 0;
        border-radius: 0;
        padding: var(--hd-5);
        background: transparent;
      }

      .foot {
        padding: 0 var(--hd-5);
      }
    }

    @media (forced-colors: active) {
      .card {
        border: 2px solid CanvasText;
      }
    }
  `,
})
export class HdCard {
  readonly hostLabel = input('You are on');
  readonly host = input.required<string>();
  readonly state = input<CardState>('idle');
}
