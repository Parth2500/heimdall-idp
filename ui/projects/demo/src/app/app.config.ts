import { provideHttpClient } from '@angular/common/http';
import {
  ApplicationConfig,
  inject,
  provideAppInitializer,
  provideBrowserGlobalErrorListeners,
} from '@angular/core';
import { provideRouter } from '@angular/router';
import { AbstractSecurityStorage, provideAuth } from 'angular-auth-oidc-client';
import { routes } from './app.routes';
import { demoAuthConfig } from './auth/auth.config';
import { DemoSession } from './auth/demo-session';
import { SplitSecurityStorage } from './auth/split-storage';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideHttpClient(),
    provideAuth({ config: demoAuthConfig(window.location.origin) }),
    // Tokens in memory, the sign-in request values in sessionStorage (U10).
    {
      provide: AbstractSecurityStorage,
      useFactory: () => new SplitSecurityStorage(sessionStorage),
    },
    // The callback must finish before the router reads the URL.
    provideAppInitializer(() => inject(DemoSession).start(window.location.href)),
    provideRouter(routes),
  ],
};
