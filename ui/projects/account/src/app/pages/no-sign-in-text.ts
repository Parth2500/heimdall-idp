import { Component } from '@angular/core';

/** The statement for a page with no stored request (U4). Sign-in without a client is not a flow yet. */
@Component({
  selector: 'acct-no-sign-in-statement',
  template: `
    <p class="hd-display" aria-hidden="true">
      Start at the app<span class="hd-display__fire">.</span>
    </p>
    <h1 class="hd-subline">No sign-in in progress</h1>
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
