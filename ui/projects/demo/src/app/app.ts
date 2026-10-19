import { Component, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { DemoSession } from './auth/demo-session';

@Component({
  selector: 'demo-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <header class="bar">
      <p class="brand">Heimdall <span>demo client</span></p>
      @if (session.state() === 'signed-in') {
        <nav aria-label="Demo screens">
          <a routerLink="/" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }"
            >Tokens</a
          >
          <a routerLink="/userinfo" routerLinkActive="active">User info</a>
          <a routerLink="/tokens" routerLinkActive="active">Refresh and theft</a>
        </nav>
        <button type="button" class="quiet" (click)="signOut()" [disabled]="signingOut()">
          Sign out
        </button>
      }
    </header>
    <main>
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
    </main>
  `,
})
export class App {
  protected readonly session = inject(DemoSession);
  private readonly router = inject(Router);
  protected readonly signingOut = signal(false);

  protected async signOut(): Promise<void> {
    this.signingOut.set(true);
    try {
      await this.session.signOut();
    } finally {
      this.signingOut.set(false);
      await this.router.navigateByUrl('/');
    }
  }
}
