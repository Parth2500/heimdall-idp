import { Component, inject, input } from '@angular/core';
import { HdFrame } from 'ui-kit';
import { BrowserNavigation } from '../session/flow';

/** The frame that every account page shares: one band, one plate, one column (U13). */
@Component({
  selector: 'acct-page',
  imports: [HdFrame],
  template: `
    <hd-frame [plateLabel]="plateLabel()" [host]="host" [busy]="busy()">
      <ng-content />
      <p hdFooter>Heimdall identity provider. Development build, not for production use.</p>
    </hd-frame>
  `,
})
export class PageFrame {
  readonly plateLabel = input('Signing in to');
  readonly busy = input(false);
  protected readonly host = inject(BrowserNavigation).host();
}
