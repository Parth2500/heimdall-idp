import { inject } from '@angular/core';
import { CanMatchFn, Router, Routes } from '@angular/router';
import { DemoSession } from './auth/demo-session';
import { HomePage } from './pages/home-page';
import { TokensPage } from './pages/tokens-page';
import { UserInfoPage } from './pages/userinfo-page';

const signedIn: CanMatchFn = () =>
  inject(DemoSession).state() === 'signed-in' || inject(Router).createUrlTree(['/']);

export const routes: Routes = [
  { path: '', component: HomePage, title: 'Heimdall demo client' },
  {
    path: 'userinfo',
    component: UserInfoPage,
    canMatch: [signedIn],
    title: 'User info · Heimdall demo',
  },
  {
    path: 'tokens',
    component: TokensPage,
    canMatch: [signedIn],
    title: 'Refresh and theft · Heimdall demo',
  },
  // The library reads the callback URL before routing starts. Then the user goes home.
  { path: 'callback', redirectTo: '' },
  { path: '**', redirectTo: '' },
];
