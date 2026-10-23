import { Component } from '@angular/core';
import { NoSignInStatement, NoSignInText } from './no-sign-in-text';
import { PageFrame } from './page-frame';

/** The signed-out page (U2). Today it says only what is true: no sign-in is in progress. */
@Component({
  selector: 'acct-signed-out-page',
  imports: [PageFrame, NoSignInStatement, NoSignInText],
  template: `
    <acct-page>
      <acct-no-sign-in-statement hdStatement />
      <acct-no-sign-in-text />
    </acct-page>
  `,
})
export class SignedOutPage {}
