import { Routes } from '@angular/router';
import { ConsentPage } from './pages/consent-page';
import { ErrorPage } from './pages/error-page';
import { LoginPage } from './pages/login-page';
import { LogoutPage } from './pages/logout-page';
import { SignedOutPage } from './pages/signed-out-page';

/** The paths that Heimdall serves under /account/ (U2, U17). */
export const routes: Routes = [
  { path: 'login', component: LoginPage, title: 'Sign in · Heimdall' },
  { path: 'consent', component: ConsentPage, title: 'Allow access · Heimdall' },
  { path: 'error', component: ErrorPage, title: 'Sign-in error · Heimdall' },
  { path: 'logout', component: LogoutPage, title: 'Sign out · Heimdall' },
  { path: 'signed-out', component: SignedOutPage, title: 'Heimdall' },
  { path: '**', redirectTo: 'signed-out' },
];
