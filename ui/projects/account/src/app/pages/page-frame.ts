import { Component, inject, input } from '@angular/core';
import { CardState, HdCard } from 'ui-kit';
import { BrowserNavigation } from '../session/flow';

/** The frame that every account page shares: the card and its host block (U16). */
@Component({
  selector: 'acct-page',
  imports: [HdCard],
  template: `
    <hd-card [hostLabel]="hostLabel()" [host]="host" [state]="state()">
      <ng-container ngProjectAs="[hdStatement]">
        <ng-content select="[hdStatement]" />
      </ng-container>
      <ng-content />
    </hd-card>
  `,
})
export class PageFrame {
  readonly hostLabel = input('You are on');
  readonly state = input<CardState>('idle');
  protected readonly host = inject(BrowserNavigation).host();
}
