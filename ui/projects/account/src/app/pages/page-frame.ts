import { Component, inject, input } from '@angular/core';
import { BridgeState, HdGate } from 'ui-kit';
import { BrowserNavigation } from '../session/flow';

/** The frame that every account page shares: the gate, its plaque, and the bridge (U15). */
@Component({
  selector: 'acct-page',
  imports: [HdGate],
  template: `
    <hd-gate [plateLabel]="plateLabel()" [host]="host" [bridge]="bridge()">
      <ng-container ngProjectAs="[hdStatement]">
        <ng-content select="[hdStatement]" />
      </ng-container>
      <ng-content />
    </hd-gate>
  `,
})
export class PageFrame {
  readonly plateLabel = input('You are at the gate of');
  readonly bridge = input<BridgeState>('idle');
  protected readonly host = inject(BrowserNavigation).host();
}
