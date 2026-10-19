import { Component } from '@angular/core';
import { NoSignInText } from './no-sign-in-text';
import { PageFrame } from './page-frame';

/** The signed-out page (U2). Today it says only what is true: no sign-in is in progress. */
@Component({
  selector: 'acct-signed-out-page',
  imports: [PageFrame, NoSignInText],
  template: `
    <acct-page plateLabel="You are on">
      <acct-no-sign-in-text />
    </acct-page>
  `,
})
export class SignedOutPage {}
