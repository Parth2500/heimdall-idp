import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { HEIMDALL_ISSUER } from './auth.config';

/** The discovery fields that the demo uses outside the library. */
export interface HeimdallEndpoints {
  readonly issuer: string;
  readonly token_endpoint: string;
  readonly userinfo_endpoint: string;
  readonly revocation_endpoint: string;
}

/**
 * Reads the endpoints from the discovery document once. The demo does not hard-code the
 * paths, so it works against any issuer that publishes them.
 */
@Injectable({ providedIn: 'root' })
export class HeimdallDiscovery {
  private readonly http = inject(HttpClient);
  private document?: Promise<HeimdallEndpoints>;

  endpoints(): Promise<HeimdallEndpoints> {
    this.document ??= firstValueFrom(
      this.http.get<HeimdallEndpoints>(`${HEIMDALL_ISSUER}/.well-known/openid-configuration`),
    ).then((doc) => {
      // OpenID Connect Discovery, section 4.3: the issuer in the document must match.
      if (doc.issuer !== HEIMDALL_ISSUER) {
        throw new Error('The discovery document names a different issuer.');
      }
      return doc;
    });
    // A failed read is not cached, so the next call tries again.
    this.document.catch(() => (this.document = undefined));
    return this.document;
  }
}
