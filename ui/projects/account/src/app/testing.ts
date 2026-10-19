import { Provider } from '@angular/core';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { BrowserNavigation } from './session/flow';

export const REQUEST_ID = '0192d7c3-0000-7000-8000-000000000001';

export function routeWith(query: Record<string, string>): Provider {
  return {
    provide: ActivatedRoute,
    useValue: { snapshot: { queryParamMap: convertToParamMap(query) } },
  };
}

export function fakeNavigation(): BrowserNavigation & { assign: ReturnType<typeof vi.fn> } {
  return { assign: vi.fn(), host: () => 'acme.localhost:7200' } as never;
}

export function text(root: HTMLElement): string {
  return (root.textContent ?? '').replace(/\s+/g, ' ').trim();
}
