import { Component, input } from '@angular/core';

/**
 * The page frame of the demo client: the band, the origin plate, the column, and the footer.
 *
 * The demo is a client, not Heimdall, so it keeps its own plain look and never carries
 * Heimdall's eye or bridge. The plate names the client's host.
 */
@Component({
  selector: 'demo-frame',
  template: `
    <header class="band">
      <div class="band__inner">
        <p class="brand">
          <span class="wordmark">{{ wordmark() }}</span>
        </p>
        <div class="band__end"><ng-content select="[hdBandEnd]" /></div>
      </div>
      @if (busy()) {
        <div class="busy" role="presentation"></div>
      }
    </header>

    <div class="sheet">
      <div class="column" [class.column--wide]="wide()">
        <p class="plate">
          <span class="plate__label">{{ plateLabel() }}</span>
          <span class="plate__host">{{ host() }}</span>
        </p>
        <main id="main" class="main" [attr.aria-busy]="busy()">
          <ng-content />
        </main>
      </div>
    </div>

    <footer class="footer">
      <div class="footer__inner"><ng-content select="[hdFooter]" /></div>
    </footer>
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      --tone: var(--hd-client);
      --tone-strong: var(--hd-client-strong);
    }

    .band {
      position: relative;
      background: var(--tone);
      color: var(--hd-on-lapis);
      overflow: hidden;
    }

    .band__inner,
    .footer__inner {
      width: min(100% - 2 * var(--hd-4), var(--hd-frame));
      margin-inline: auto;
    }

    .band__inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: var(--hd-4);
      min-height: var(--hd-band-height);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: var(--hd-3);
    }

    .wordmark {
      font-size: var(--hd-text-l);
      font-weight: 800;
      letter-spacing: -0.01em;
      line-height: 1;
    }

    .band__end {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: var(--hd-4);
      color: var(--hd-on-lapis);
    }

    .busy {
      position: absolute;
      inset: auto 0 0 0;
      height: 3px;
      overflow: hidden;
    }

    .busy::after {
      content: '';
      position: absolute;
      inset: 0;
      width: 40%;
      background: var(--hd-on-lapis);
      animation: hd-busy 1.1s var(--hd-ease-out) infinite;
    }

    .sheet {
      flex: 1;
      background: var(--hd-page);
      padding-bottom: var(--hd-16);
    }

    .column {
      width: min(100% - 2 * var(--hd-4), var(--hd-frame));
      margin-inline: auto;
    }

    .main {
      max-width: var(--hd-column);
      padding-top: var(--hd-12);
    }

    .column--wide .main {
      max-width: 48rem;
    }

    /* The signature move: the plate hangs from the band like a ribbon tab. */
    .plate {
      display: inline-flex;
      flex-direction: column;
      gap: var(--hd-1);
      max-width: 100%;
      padding: var(--hd-3) var(--hd-4) var(--hd-4);
      background: var(--tone);
      color: var(--hd-on-lapis);
      clip-path: polygon(0 0, 100% 0, 100% 100%, 50% calc(100% - 0.5rem), 0 100%);
    }

    .plate__label {
      color: var(--hd-on-lapis-muted);
      font-size: var(--hd-text-xs);
      font-weight: 600;
    }

    .plate__host {
      font-family: var(--hd-mono);
      font-size: var(--hd-text-m);
      font-weight: 700;
      overflow-wrap: anywhere;
    }

    .footer {
      border-top: 1px solid var(--hd-rule);
      background: var(--hd-ground);
      color: var(--hd-ink-muted);
      font-size: var(--hd-text-xs);
      padding-block: var(--hd-6);
    }
  `,
})
export class ClientFrame {
  readonly wordmark = input.required<string>();
  readonly plateLabel = input.required<string>();
  readonly host = input.required<string>();
  readonly busy = input(false);
  readonly wide = input(false);
}
