import { Component } from '@angular/core';

/** The title for a page with no stored request (U4). Sign-in without a client is not a flow yet. */
@Component({
  selector: 'acct-no-sign-in-statement',
  template: `
    <h1 class="hd-title">No sign-in in progress</h1>
    <p class="hd-subtitle">Start at the app.</p>
  `,
})
export class NoSignInStatement {}

/** The panel text for a page with no stored request (U4). */
@Component({
  selector: 'acct-no-sign-in-text',
  template: `
    <p class="hd-lead">
      You sign in to Heimdall through an app. Go back to the app you want to use, then choose its
      sign-in option.
    </p>
  `,
})
export class NoSignInText {}
