import { Component, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { HdFrame } from 'ui-kit';
import { DemoSession } from './auth/demo-session';

@Component({
  selector: 'demo-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, HdFrame],
  template: `
    <hd-frame
      tone="client"
      wordmark="Demo client"
      plateLabel="A Heimdall client app on"
      [host]="host"
      [busy]="session.state() === 'starting' || session.state() === 'redirecting' || signingOut()"
      [wide]="true"
    >
      @if (session.state() === 'signed-in') {
        <nav hdBandEnd class="nav" aria-label="Demo screens">
          <a
            routerLink="/"
            routerLinkActive="active"
            [routerLinkActiveOptions]="{ exact: true }"
            ariaCurrentWhenActive="page"
            >Tokens</a
          >
          <a routerLink="/userinfo" routerLinkActive="active" ariaCurrentWhenActive="page"
            >User info</a
          >
          <a routerLink="/tokens" routerLinkActive="active" ariaCurrentWhenActive="page"
            >Refresh and theft</a
          >
          <button
            type="button"
            class="hd-button hd-button--quiet"
            (click)="signOut()"
            [attr.aria-disabled]="signingOut()"
          >
            Sign out
          </button>
        </nav>
      }

      @switch (session.state()) {
        @case ('starting') {
          <p role="status">Checking the sign-in state.</p>
        }
        @case ('redirecting') {
          <p role="status">Sending you to Heimdall.</p>
        }
        @default {
          <router-outlet />
        }
      }

      <p hdFooter>
        Sample client for the Heimdall identity provider. It keeps tokens in memory only.
        Development build, not for production use.
      </p>
    </hd-frame>
  `,
  styles: `
    .nav {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: var(--hd-4);
    }

    .nav a {
      color: var(--hd-on-lapis);
      text-decoration: none;
      font-weight: 600;
      padding-block: var(--hd-1);
      border-bottom: 3px solid transparent;
    }

    .nav a:hover {
      border-bottom-color: var(--hd-on-lapis-muted);
    }

    .nav a.active {
      border-bottom-color: var(--hd-on-lapis);
    }
  `,
})
export class App {
  protected readonly session = inject(DemoSession);
  private readonly router = inject(Router);
  protected readonly signingOut = signal(false);
  protected readonly host = window.location.host;

  protected async signOut(): Promise<void> {
    if (this.signingOut()) {
      return;
    }
    this.signingOut.set(true);
    try {
      await this.session.signOut();
    } finally {
      this.signingOut.set(false);
      await this.router.navigateByUrl('/');
    }
  }
}
