import { APP_BASE_HREF } from '@angular/common';
import { provideHttpClient, withXsrfConfiguration } from '@angular/common/http';
import {
  ApplicationConfig,
  inject,
  provideAppInitializer,
  provideBrowserGlobalErrorListeners,
} from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import { SessionApi } from './session/session-api';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    // Double submit: Angular copies the __Host-XSRF-TOKEN cookie into the header, for relative
    // URLs only, so the token never goes to another origin (U7).
    provideHttpClient(
      withXsrfConfiguration({ cookieName: '__Host-XSRF-TOKEN', headerName: 'X-XSRF-TOKEN' }),
    ),
    provideRouter(routes),
    // No <base> element: the policy has base-uri 'none' (U3). Every page is one level under
    // /account/, so the relative bundle URLs in index.html still resolve there.
    { provide: APP_BASE_HREF, useValue: '/account/' },
    // Sets the antiforgery cookie once. A failure here shows up as an error on the first POST.
    provideAppInitializer(() =>
      inject(SessionApi)
        .csrf()
        .catch(() => undefined),
    ),
  ],
};
