# Heimdall Threat Model (Phase 0)

Method: STRIDE for each trust boundary. References: RFC 6749, RFC 7636 (PKCE), RFC 7009 (revocation), RFC 9700 (OAuth Security BCP), RFC 9207 (issuer identification), OAuth 2.1 draft.

Writing rules are in `CLAUDE.md`. They follow ASD-STE100 style, applied by hand.

## Glossary

Each term has one meaning in this document. Do not use a synonym.

| Term | Meaning |
|---|---|
| Heimdall | This identity provider. It is also the issuer. |
| Tenant | An isolated domain with its own users, clients, keys, and settings. One Heimdall installation can host many tenants. |
| Client | An application that asks Heimdall for tokens. A client belongs to exactly one tenant. |
| Public client | A client that cannot keep a secret (single-page app, mobile app). |
| Confidential client | A client that can keep a secret (server application). |
| Resource server | An API that accepts Heimdall access tokens. |
| Audience | The resource server that a token is for. It is the `aud` claim. A client asks for one with the `resource` parameter (RFC 8707). |
| Subject | The user that an access token or ID token identifies. |
| Code | An authorization code. It is single-use and short-lived. |
| Redeem | To exchange a code for tokens at `/token`. |
| Access token | A short-lived JWT that a client sends to a resource server. |
| Refresh token | An opaque token that a client exchanges for new tokens. |
| Family | All refresh tokens that come from one code redemption. Each family has one `TokenFamilyId`. |
| Rotate | To replace a refresh token with a new one each time the client uses it. |
| Key rotation | To replace a tenant's active signing key with the next key on a schedule. The old key stays in the JWKS until its last token expires. |
| Reuse | A second use of a code or refresh token that is already used. |
| Revoke | To make a token or family permanently invalid. |
| Bearer | A token that gives access to anyone who holds it. |
| PKCE | Proof Key for Code Exchange. It binds a code to the client that asked for it. |
| Verifier, challenge | The `code_verifier` is a secret from the client. The `code_challenge` is its SHA-256 hash. |
| JWKS | The public key set that Heimdall publishes. Resource servers use it to check signatures. |
| `kid` | The key identifier. It tells a verifier which key in the JWKS signed a token. Heimdall uses the RFC 7638 thumbprint of the public key. |
| Key store | The component that holds the private signing keys and signs with them. The keys never leave it. Key Vault or KMS on deployment. A local file in development. |
| Hash | A one-way digest of a secret. Heimdall stores hashes, not secrets. |
| Throttle | To slow or limit requests. It does not lock out the caller. |
| Audit log | An append-only record of security events. |
| Protocol rejection | Heimdall refuses a request before the grant runs, because the request breaks the HTTP or OAuth format. Heimdall logs it. |
| Grant rejection | The grant refuses a well-formed request, for example for a wrong secret or a scope that is not allowed. Heimdall audits it. |

## Trust boundaries

| # | Boundary | Other side | Trust level |
|---|---|---|---|
| B1 | User agent <-> Heimdall | Browser. It can have malicious extensions. A client can have XSS. | Untrusted |
| B2 | Client <-> Heimdall | Registered clients. A client can be compromised or impersonated. | Untrusted until authenticated. Public clients are never authenticated. |
| B3 | Heimdall <-> Postgres | Persistence | Trusted. Assume a read-only leak is possible (backup, SQL injection). |
| B4 | Heimdall <-> key store | Signing keys. A file or database now. Key Vault or KMS on deployment. | Highest-value asset |
| B5 | Resource server <-> Heimdall | Anyone on the internet. Requests are unauthenticated reads (JWKS). | Untrusted |

## Cross-cutting decisions

These decisions apply to every endpoint. The tables below refer to them by ID.

| ID | Decision | Reason |
|---|---|---|
| D1 | Use TLS only. Set HSTS on the issuer origin. | Every secret in OAuth is a bearer value on the network. |
| D2 | Require PKCE with `S256` for all clients. Reject `plain`. | This is OAuth 2.1. A stolen code is useless without the verifier. |
| D3 | Store codes, refresh tokens, and client secrets as hashes only. Generate each with 256 bits of randomness. Use SHA-256. Use Argon2id for user passwords only. | A leak of the database must not give an attacker usable credentials. Random 256-bit values do not need a slow hash. |
| D4 | Compare secrets with `CryptographicOperations.FixedTimeEquals` on the hashes. | This removes the timing side channel. |
| D5 | Return the same error for each failure of one kind. Return `invalid_client` for an unknown client or a wrong secret. Return `invalid_grant` for an unknown, expired, used, or mismatched code or refresh token. Write the real reason to the audit log only. | An attacker cannot learn which part was wrong. |
| D6 | Send `Cache-Control: no-store` and `Pragma: no-cache` on token responses. | RFC 6749, section 5.1. |
| D7 | Never log secrets, codes, verifiers, refresh tokens, or client assertions. Log a correlation ID. | Logs are widely readable and kept for a long time. |
| D8 | Sign access tokens as JWTs with `RS256` only. Do not negotiate `alg`. Put `kid` in the header. Set the lifetime to 5 minutes. Make refresh tokens opaque. | A short lifetime limits the damage from theft. A fixed `alg` stops `none` and HS256 confusion attacks. |
| D9 | Add `iss` to the authorization response (RFC 9207). | This stops mix-up attacks. |
| D10 | In version 1, confidential clients use `client_secret_basic`. Public clients use no authentication and PKCE. Add `private_key_jwt` in Phase 2. | Start with the smallest correct surface. |
| D22 | Each client has a list of allowed audiences. A token has exactly one audience. The client names it with the `resource` parameter (RFC 8707). If the client has only one audience, that audience is the default. An unknown resource returns `invalid_target`. A token from a user's grant can also name the tenant's userinfo endpoint. That endpoint is the default for a client with no audience. A `client_credentials` token never names it. | A token for one API cannot be replayed at another API. A resource server cannot use its token to read user claims at `/userinfo`. |

## `GET /oauth/v1/authorize` (worked example)
| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | A rogue client registers a redirect URI that looks like a real one. | Heimdall compares redirect URIs by exact match. It allows no wildcards. An admin must approve each client registration. |
| Tampering | An attacker changes the `code_challenge` on the network. | TLS (D1). PKCE also stops a man-in-the-middle from using a stolen code. |
| Repudiation | A user says they did not grant consent. | Heimdall writes `consent.granted` or `consent.denied` for each decision, with the user, client, scope, IP, and correlation ID. Persisted consent records come in Phase 3. |
| Information disclosure | A code leaks through browser history, the referrer header, or logs. | A code is single-use and expires after 5 minutes. Heimdall never writes a full code to a log (D7). |
| Denial of service | A flood of `/authorize` requests uses all database resources. | Rate limit for each IP and each `client_id`. |
| Elevation of privilege | A client requests more scope than it is allowed. | Heimdall checks the requested scope on the server against the `AllowedScopes` of the client. It refuses extra scope. It does not reduce it. |
| Tampering | Open redirect: an attacker puts an unregistered `redirect_uri` in the link, so an error carries the user to the attacker's site. | Until `client_id` and `redirect_uri` pass the exact-match check, Heimdall shows its own error and never redirects (RFC 6749, section 4.1.2.1). A repeated parameter also gets this error. |
| Spoofing | Mix-up: a client that uses several servers sends a code to the wrong one. | Every redirect from `/authorize` carries `iss`, on success and on error (RFC 9207, D9). |
| Tampering | The browser changes the request between login and the code. | Heimdall stores the checked request. The login page and the resume step get only the request ID. One request gives one code, enforced by the `DELETE` in the code transaction. |

## `POST /oauth/v1/token`

Grants: `authorization_code`, `client_credentials`, `refresh_token`. Boundary: B2.

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | An attacker uses a leaked or guessed secret to act as a confidential client. | Heimdall generates the secrets with high entropy and stores hashes (D3). It compares in fixed time (D4). It throttles failures for each `client_id`. During rotation, two secrets are valid at the same time. |
| Spoofing | The `client_credentials` grant has no user and no PKCE. The secret is the only defense. | Heimdall enables this grant for each client separately. This risk is the reason to add `private_key_jwt` or mTLS later. |
| Spoofing | An attacker claims the `client_id` of a public client. | Heimdall does not authenticate public clients. It binds the code to the client and to the PKCE verifier instead (D2). |
| Spoofing | Confused deputy: an attacker redeems a code that Heimdall issued to a different client. | The stored `client_id` of the code must equal the calling client. The `redirect_uri` must equal the value sent to `/authorize`, if the client sent one. |
| Spoofing | An attacker learns which clients exist from error messages or response time. | Heimdall uses uniform errors (D5). For an unknown `client_id`, it still compares against a dummy hash, so the response time is the same. |
| Spoofing | An attacker replays a stolen refresh token from another machine. | Rotation and family revocation on reuse. See "Refresh flow". DPoP adds sender-constraining in Phase 2. |
| Spoofing | An attacker poses as Heimdall to the client (mix-up). | TLS and HSTS (D1). The `iss` parameter in the authorization response (D9). |
| **Tampering** | A request repeats a parameter, such as `grant_type`, `code`, or `client_id`. | Heimdall rejects a request with a repeated parameter. It accepts only `application/x-www-form-urlencoded`. |
| Tampering | A client sends credentials in the query string. Proxies and logs capture them. | Heimdall reads parameters from the POST body and the `Authorization` header only. It rejects the query string. |
| Tampering | PKCE downgrade: the challenge uses `plain`, or the verifier is missing. | `/authorize` rejects `plain`. `/token` requires `code_verifier`. It checks that `BASE64URL(SHA256(verifier))` equals the stored challenge, in fixed time. The verifier has 43 to 128 unreserved characters. |
| Tampering | An attacker forges an access token, or uses `alg=none` or HS256 confusion. | Heimdall signs with `RS256` only (D8). The documentation tells resource servers to pin `RS256` too. |
| Tampering | An attacker changes a code or token in the database. | Heimdall stores hashes only. The database enforces a unique `CodeHash` and a non-null `ClientId`. Access to the key store is restricted (B4). |
| **Repudiation** | A client or user denies a redemption or issuance. After a theft, no evidence exists. | Heimdall writes one audit record for each issuance, redemption, grant rejection, and family revocation. The record has: timestamp, `client_id`, subject, grant type, result, source IP, correlation ID. The table is insert-only. The application role has no update or delete right. An immutable store is a Phase 3 item. |
| Repudiation | Malformed requests fill the audit table. Each one costs a database write before any check. | Heimdall logs a protocol rejection and does not audit it. Examples are a query string, a wrong content type, or a repeated parameter. The log line has the error code, the reason, and the correlation ID. It has no parameter value (D7). Decided on 2026-10-18. |
| **Information disclosure** | A browser or proxy caches tokens or secrets. | `no-store` (D6). |
| Information disclosure | Secrets, codes, verifiers, or tokens appear in logs, traces, or exception messages. | D7. Request logging for this route excludes the body and the `Authorization` header. |
| Information disclosure | A database leak (backup, SQL injection) gives an attacker live credentials. | Heimdall stores hashes only (D3). It uses parameterized queries only (EF Core). |
| Information disclosure | An error response shows why a code failed (expired, used, or wrong client). | D5. Only the audit log has the reason. |
| Information disclosure | An access token holds more claims than the resource server needs. | The token holds only `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, and `client_id`. Personal data goes only in the ID token and `/userinfo`, and only if the scope allows it. |
| **Denial of service** | A flood of `/token` requests uses all database connections or CPU. | Rate limit for each IP and each `client_id`. Body size limit. Short timeouts. Heimdall rejects malformed requests before any database call. |
| Denial of service | An attacker sends wrong secrets on purpose to lock out a victim client. | Heimdall throttles. It does not lock. The real client stays able to authenticate. |
| Denial of service | Many requests redeem one code at the same time and hold row locks. | One atomic statement: `UPDATE ... WHERE redeemed_at IS NULL AND expires_at > now() RETURNING ...`. A losing request gets zero rows and returns at once. No lock is held for long. |
| **Elevation of privilege** | Two requests redeem the same code at the same time (race). Both get tokens. | The atomic conditional update above, with a unique index on `CodeHash`. A check in application code, followed by an update, is not allowed. |
| Elevation of privilege | An attacker replays a captured code after redemption. | The conditional update affects zero rows on a redeemed code. Heimdall treats this as reuse. It revokes the family that came from that code, writes `code.reuse_detected` and `family.revoked`, and raises an alert (a Critical log line with the event name `SecurityAlert`). It does not revoke all sessions of the user and client pair. |
| Denial of service | An attacker with a stolen code but no verifier tries to burn it, so the real client fails. | The client, the redirect URI, and the PKCE challenge are part of the conditional update. A wrong value matches no row and changes nothing. |
| Elevation of privilege | A client requests a grant it may not use, such as `client_credentials` from a public client. | Each client has an `AllowedGrantTypes` list, checked here. Only confidential clients can use `client_credentials`. |
| Elevation of privilege | A token for one resource server is replayed at another resource server. | Each token has exactly one audience from the client's allowed list (D22). Resource servers check `aud`. |
| Elevation of privilege | A `client_credentials` client requests user scopes such as `openid`. | Heimdall returns `invalid_scope`. A token without a user cannot carry user scopes. |
| Elevation of privilege | A client requests more scope at `/token` than the user approved. | The issued scope is the overlap of the code's approved scope and the client's `AllowedScopes`. Refresh can only reduce scope. |
| Elevation of privilege | A client redeems a code with a different `redirect_uri` or `client_id`. | Heimdall compares with the stored values by exact match. A mismatch returns `invalid_grant` (D5). |

## Refresh flow

Boundary: B2. A refresh token is opaque and single-use. It belongs to a family. The family starts at the code redemption.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker uses a stolen refresh token. | Each use returns a new refresh token and marks the old one as used (`ReplacedByTokenHash`). Reuse of a used token revokes the whole family at once, in the same transaction as the check. Confidential clients also authenticate. DPoP protects public clients in Phase 2. |
| Spoofing | A client presents a token that Heimdall issued to a different client. | The family's client must equal the calling client. The check is part of the rotation statement, so the wrong client cannot use or burn the token. |
| Tampering | The real client and an attacker present the same token at the same time. Two retries can also cause this. | Rotation is one atomic conditional update on `used_at IS NULL`. One caller wins. Heimdall treats the other caller as reuse. |
| Tampering | A client asks for more scope on refresh. | The requested scope must be a subset of the original grant. |
| Repudiation | No record shows who rotated a token or why a family ended. | Heimdall writes an audit event for each rotation, reuse detection, and revocation. It includes the family ID and the correlation ID. |
| Information disclosure | An attacker reads tokens from the database. | Heimdall stores SHA-256 hashes only (D3). The plain token appears once, in the response (D6). |
| Denial of service | An attacker with a stolen token triggers reuse on purpose, so the victim loses the session. | Accepted. The victim signs in again. This failure is safer than leaving a live session to the thief. Alerts make the pattern visible. |
| Denial of service | A real client retries after it loses a response and triggers reuse detection. | Decision: no grace window. A grace window reopens the race that reuse detection closes. A client must save the new token before it uses it. The integration guide states this. |
| Denial of service | Expired tokens and families fill the database. | A scheduled job deletes expired families. Indexes exist on `TokenFamilyId` and `TokenHash`. |
| Elevation of privilege | A client rotates forever and keeps a session without end. | The family has an absolute lifetime (for example, 30 days) and an idle timeout. Rotation does not extend either one. A user or admin revocation ends the whole family. |
| Elevation of privilege | A refresh succeeds after the user account is disabled or consent is removed. | On each refresh, Heimdall checks that the user is active and consent exists. If not, it returns `invalid_grant` and revokes the family. The consent check comes with persisted consent (Phase 3). Until then, consent is a decision for one stored request. No stored consent exists that a user could remove. |

## `/.well-known/jwks.json`

Boundary: B5. The endpoint is public, unauthenticated, read-only, and has high request volume.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker serves a fake JWKS (DNS or man-in-the-middle). Forged tokens then pass checks. | TLS and HSTS (D1). Resource servers fetch keys only from the configured issuer. They take `jwks_uri` from discovery over TLS. They ignore `jku` and `x5u` headers in tokens. |
| Tampering | An attacker changes the key set that Heimdall serves. | Heimdall serves the set from memory, built from the key store. Only the key-management component can write to the key store (B4). On deployment, Key Vault or KMS holds the keys. |
| Tampering | The endpoint exposes private key material. | The response contains only public fields: `kty`, `n`, `e`, `kid`, `use`, `alg`. A separate public-key type makes it impossible to serialize private fields. |
| Repudiation | It is not clear which key signed a disputed token. | Each token header has a `kid`. Heimdall writes each key event to the audit log: created, activated, retired, removed. |
| Information disclosure | Retired-key data or key store details leak. | The JWKS lists only active keys and keys in the overlap period. It shows no internal identifier except `kid`. |
| Denial of service | Many requests hit the database for each call. | Heimdall caches the keys in memory and refreshes the cache on rotation. It sends `Cache-Control: public, max-age=...` and an `ETag`. A CDN or reverse proxy sits in front on deployment. An IP rate limit is the backstop. |
| Denial of service | All resource servers refetch the JWKS at the same time after a rotation. | `max-age` spreads the refetch times. Resource servers throttle refetches for an unknown `kid`. The documentation states this. |
| Elevation of privilege | An attacker steals a signing key and creates valid tokens. | Emergency procedure: an operator runs `remove-key <tenant host> <kid>`. The key leaves the JWKS at once. Tokens that this key signed stop working. This cost is accepted. Heimdall then activates a ready next key, or creates a new key. Token issuance stops until the new key is active, at most one publish wait. Key Vault or KMS keeps private keys non-exportable. Each server reloads its active key within the server key cache lifetime. Until then, another server can still sign with the removed key. Resource servers reject those tokens after their JWKS cache expires. |
| Elevation of privilege | Rotation breaks live tokens. Or a new key signs before caches know it. | Publish the new key in the JWKS at least one cache lifetime before it signs a token. The wait also covers the server key cache lifetime, because another server can serve the old JWKS for that long. Keep the old `kid` listed until its last token expires (token lifetime plus clock skew). |

## `POST /oauth/v1/revoke` (RFC 7009)

Boundary: B2. The endpoint revokes a refresh token with its family, or an access token.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker revokes the tokens of another client. | Confidential clients authenticate as at `/token` (D4, D5). The family's client must equal the caller. On a mismatch, Heimdall revokes nothing, returns `200`, and writes `revocation.refused`. |
| Spoofing | An attacker guesses client secrets at `/revoke`, because it is not `/token`. | Heimdall audits each failed client authentication at `/revoke` as `revocation.refused`, as it does at `/token`. |
| Spoofing | A public client revokes with a stolen token. | The refresh token is already a bearer secret. Whoever holds it can revoke it. Revocation only helps the real owner. |
| Tampering | A request repeats a parameter or sends credentials in the query string. | The same rules as `/token`: form body only, no repeated parameters. |
| Repudiation | A user or client disputes a revocation. | Heimdall writes `family.revoked` for each revoked family. The event has the family ID, the client, the caller IP, and the correlation ID. The family reason is `user_logout`. A request that revokes nothing goes to the log only. |
| Information disclosure | The response shows whether a token existed or was valid. | Heimdall returns `200` for an unknown, expired, revoked, or foreign token (RFC 7009, section 2.2). Only a malformed request or failed client authentication gets an error. |
| Denial of service | An attacker sends many revocations to flood or lock rows. | Rate limit for each IP and each `client_id`. Revocation is one indexed update on `TokenFamilyId`. |
| Elevation of privilege | A revoked refresh token family continues to work. | Heimdall revokes the whole family with one statement. This includes the newest refresh token. Any token of the family revokes it, also a used one. This is not reuse, because revocation only removes access. |
| Elevation of privilege | A revoked access token still works until it expires. | Accepted risk. Access tokens are stateless JWTs with a lifetime of 5 minutes (D8). Version 1 has no denylist. Phase 2 adds introspection (RFC 7662) for resource servers that need immediate revocation. |

## `GET /oauth/v1/userinfo`

Boundary: B2 and B5. The endpoint needs a bearer access token. It returns the claims of the subject.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker sends a forged token, or a token for a different issuer or audience. | Heimdall checks the signature with `RS256` only (D8), with the tenant's published keys from memory. The `typ` must be `at+jwt`, so an ID token fails. It checks `iss`, `exp`, and that `aud` is the userinfo endpoint (D22). It rejects `client_credentials` tokens, because their subject is not a user. |
| Spoofing | An attacker replays a stolen access token. | The short lifetime (D8). DPoP adds sender-constraining in Phase 2. |
| Tampering | A client sends the token in the query string or form body. Logs and caches keep it. | Heimdall accepts the `Authorization: Bearer` header only. A token in the query string gets `invalid_request`, so the client developer sees the mistake. |
| Repudiation | A party disputes access to user data. | Heimdall writes `userinfo.read` for each successful call: `sub`, `client_id`, released scopes, correlation ID. It does not log claim values. A refused call goes to the log only. |
| Information disclosure | The response gives more claims than the scope allows. | Heimdall releases only the claims that the granted scopes allow. Today `email` releases `email` and `email_verified`. `email_verified` is always false, because Heimdall has no email verification yet. The `sub` always equals the `sub` of the ID token. |
| Information disclosure | A browser or proxy caches the response. | `Cache-Control: no-store`. CORS allows only registered client origins. It never uses `*`. Until the Angular SPA work, Heimdall sends no CORS headers, so a browser blocks every cross-origin read. |
| Information disclosure | An error response shows details. | Heimdall returns a generic `invalid_token` error with no reason (D5). |
| Denial of service | A flood of calls causes one database read for each call. | Rate limit for each subject and each IP. Heimdall loads claims by primary key. A short-lived cache of user claims is optional. |
| Elevation of privilege | A disabled or deleted user, or removed consent, still gets data until the token expires. | Heimdall loads the user on each call. It rejects an inactive user. This check is stricter than a JWT check alone. The consent check comes with persisted consent (Phase 3). |
| Elevation of privilege | A token with only the `openid` scope reads profile claims. | Heimdall maps scopes to claims on the server. |

## User login, session, and consent pages

Boundary: B1. Heimdall shows these pages in the user's browser. `/authorize` sends the user here when no valid session exists, or when consent is missing.

Additional decisions for this boundary:

| ID | Decision | Reason |
|---|---|---|
| D11 | The session cookie uses the `__Host-` prefix and the flags `Secure`, `HttpOnly`, and `SameSite=Lax`. It has no `Domain` attribute. | `Lax` is required. A client sends the user to `/authorize` with a top-level cross-site navigation. `Strict` would drop the cookie, and the user would appear signed out. |
| D12 | The cookie holds a random 256-bit session ID. The server stores the session and a hash of the ID. | The browser holds no user data. The server can end a session at any time. |
| D13 | Heimdall issues a new session ID at sign-in. | This stops session fixation. |
| D14 | A password has at least 12 characters and at most 128. Heimdall rejects passwords from a breached-password list. It has no composition rules. | This follows NIST SP 800-63B. Length and the breach check protect users better than character rules. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | Credential stuffing: an attacker tries leaked passwords from other sites. | Heimdall limits sign-in attempts for each IP. It throttles failures for each account and source: after 5 failures, the wait doubles with each failure, up to 15 minutes. During a wait, Heimdall does not check the password, so guessing makes no progress. The attempt costs one dummy hash and gets the generic failure, so a throttled account looks like any failed sign-in. It does not lock the account (see denial of service). It checks passwords against a breached-password list (D14). Multi-factor authentication with WebAuthn comes in Phase 3. |
| Spoofing | An attacker learns which accounts exist from the login error or the response time. | Heimdall returns one generic error for an unknown user and a wrong password. For an unknown user, it still computes an Argon2id hash against a dummy value, so the response time is the same. |
| Spoofing | Session fixation: an attacker sets a known session ID before sign-in. | Heimdall issues a new session ID at sign-in (D13). It never accepts a session ID from the URL. |
| Spoofing | An attacker steals the session cookie. | `HttpOnly` blocks script access. `Secure` and HSTS (D1) block network capture. The session has an idle timeout and an absolute lifetime. |
| Spoofing | Login CSRF: an attacker signs the victim in to the attacker's account. | The login form has an anti-forgery token. `SameSite=Lax` also applies (D11). |
| Spoofing | CSRF on the JSON login API that the Angular page calls (`/session/v1/login` and `/logout`). | Three layers. The page sends the antiforgery token from the `__Host-XSRF-TOKEN` cookie in the `X-XSRF-TOKEN` header (double-submit). The API accepts only JSON, and a cross-site script needs a CORS preflight for JSON, which Heimdall never allows. A browser `Origin` header must equal the tenant origin. |
| Information disclosure | A cross-origin script reads a session API response, such as `/session/v1/me`. | Heimdall sends no CORS headers, so the browser blocks the read. The responses are `no-store`. |
| **Tampering** | CSRF on the consent form: an attacker's page submits consent for the victim. | The consent API (`POST /session/v1/consent`) has the same three CSRF layers as the login API. Heimdall links the decision to the pending authorization request stored on the server. The browser cannot change the client or the scope. |
| Spoofing | A second user signs in on the same browser and uses the first user's consent decision. | The stored request records the user who decided. A decision counts only for that user. |
| Elevation of privilege | A user denies consent, and a script then approves the same request. | A denial ends the stored request at the resume step. A later decision or resume finds no request. |
| Tampering | A user or script changes the client or scope in the consent form. | Heimdall reads the client and scope from the stored request. The API accepts only the request ID and the decision. |
| Tampering | Open redirect: the post-login return URL sends the user to an attacker's site. | Heimdall returns only to a stored `/authorize` request. It accepts no free-form return URL. |
| Tampering | Clickjacking: an attacker frames the login or consent page and tricks the user into a click. | Heimdall sends `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY` on these pages. |
| **Repudiation** | A user says they did not sign in, or did not log out. | Heimdall writes an audit event for each sign-in, failure, consent, and logout. The event has the session ID hash, IP, user agent, and correlation ID. |
| **Information disclosure** | The password, session ID, or CSRF token appears in logs or URLs. | D7. Heimdall sends the password only in a POST body over TLS. The session ID is only in the cookie. |
| Information disclosure | Cross-site scripting (XSS) on a Heimdall page reads page data or acts as the user. | Heimdall encodes all output. It sends a strict `Content-Security-Policy`. It uses no inline script. XSS can read the antiforgery request token, which that pattern accepts. XSS cannot read the session cookie, because it is `HttpOnly`. |
| Tampering | A compromised npm package in the Angular build runs in the login page (supply chain). | Open: decide with the Angular work. Options are a lockfile with integrity hashes, a dependency review in CI, and a strict CSP with no third-party script origins. |
| Information disclosure | The consent page shows client data that an attacker controls, such as the client name. | Heimdall encodes the name. An admin approves the client registration (see `/authorize`). Heimdall shows the registered redirect URI host. |
| **Denial of service** | An attacker sends failed logins on purpose to lock out a victim. | Heimdall throttles. It does not lock. The throttle is for each account and source, so the attacker's failures slow only the attacker's source. The real user at another address can still sign in. A distributed attacker with many addresses gets a separate wait at each one, and the IP rate limit still applies to each. |
| Denial of service | Argon2id costs much CPU and memory. An attacker sends many login requests. | Rate limit for each IP before the hash runs. A limit on the number of concurrent hash operations. |
| **Elevation of privilege** | A session stays valid after a password change or account disable. | Heimdall ends all sessions of the user on password change and on disable. It checks the user status on each `/authorize` request. |
| Elevation of privilege | Logout CSRF: an attacker's page ends the victim's session. | Logout needs a POST with an anti-forgery token. |
| Elevation of privilege | A session never ends. | The session has an idle timeout and an absolute lifetime. Neither one extends the other. |

Out of scope for now: registration, email verification, password reset, and account recovery. Each one needs its own table. They are the most common route to account takeover, so add them before any public deployment.

## Tenants and client configuration

Boundaries: B2 and B3. Heimdall is multi-tenant. The schema has a `Tenant` table from the first migration. Tenant administration features (portal, onboarding) arrive in Phase 3.

Decisions for this area:

| ID | Decision | Reason |
|---|---|---|
| D15 | Settings have three layers: platform defaults, tenant settings, and client settings. The most specific layer wins. Each layer must stay inside the limits of the layer above. | A tenant or client cannot weaken a platform rule. |
| D16 | The platform sets a minimum and a maximum for each setting. Heimdall rejects a value outside the range when the admin saves it. | Misconfiguration cannot create an insecure policy. |
| D17 | These rules have no setting: PKCE with `S256`, `RS256` only, exact-match redirect URIs, family revocation on reuse, no grace window, and hashing at rest. | The weakest client must not set the security of all clients. |
| D18 | The login session lifetime is a tenant setting. A client cannot lengthen it. A client can make it shorter with `max_age`. | The session cookie is shared by all clients of a tenant (single sign-on). |
| D19 | Each tenant has its own issuer URL, user pool, clients, and signing keys. Each token carries the tenant's `iss`. | A token from tenant A must not be valid in tenant B. |
| D20 | Every tenant-owned table has a `TenantId` column. Each unique index includes `TenantId`. EF Core global query filters apply `TenantId` to every query. PostgreSQL row-level security is a second layer. | One missed filter must not expose another tenant's data. |
| D21 | Heimdall finds the tenant from the host name (one subdomain for each tenant). | Each tenant gets its own browser origin and its own `__Host-` cookie. Path-based tenants would share one cookie. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | A token from tenant A is accepted by a resource server or endpoint of tenant B. | Each tenant has its own `iss` and signing keys (D19). Resource servers check `iss` and `aud`. `/userinfo` checks that the token's tenant equals the request's tenant. |
| Spoofing | A user of tenant A signs in with a session from tenant B. | The server-side session stores `TenantId`. Heimdall rejects a session whose tenant differs from the request's tenant. |
| **Tampering** | A client admin sets a policy outside the limits, such as a very long token lifetime. | Heimdall validates each value against the limits on save (D16). The database has check constraints for the same ranges. |
| Tampering | An attacker adds a redirect URI to a client. | A change to redirect URIs needs approval from a tenant admin or a platform admin. Heimdall writes an audit event. |
| **Repudiation** | A configuration change has no record. | Heimdall writes an audit event for each change, with the old value, the new value, the admin, and the tenant. |
| **Information disclosure** | A query without a tenant filter returns data of another tenant (insecure direct object reference). | D20. The EF Core filter is the first layer. PostgreSQL row-level security is the second layer: it also covers raw SQL. The application login is not a superuser, so the policies apply to it. Tests create two tenants and check that each endpoint refuses cross-tenant IDs. Other tests bypass the EF Core filter and check that PostgreSQL still refuses. |
| Information disclosure | An attacker learns which tenants exist from error messages or response time. | Heimdall returns the same response for an unknown tenant host and for a host with no content. |
| Spoofing | A client sends `X-Forwarded-For` or `X-Forwarded-Proto` to fake its address in the audit log or to pass the HTTPS check over plain HTTP. | Heimdall reads these headers only from the proxies in `Heimdall:ForwardedHeaders`. With none configured, it reads no forwarded header. It reads one hop only: the rightmost value, which the trusted proxy wrote. |
| Spoofing | A client sends `X-Forwarded-Host` to choose another tenant or issuer. | Heimdall never reads `X-Forwarded-Host`. The proxy must pass the original Host header (D21). |
| **Denial of service** | One tenant uses all capacity (noisy neighbor). | Rate limits apply for each tenant, each client, each IP, and each account. |
| **Elevation of privilege** | A tenant admin changes platform settings or another tenant. | Admin roles are separate: platform admin and tenant admin. Each admin API call checks the role and the `TenantId`. |
| Elevation of privilege | An admin disables a client or revokes a secret, but other servers still accept it. | Each server keeps a tenant's clients in memory for the server cache lifetime (1 minute). The server that makes the change drops its entry at once. This delay is accepted. Secret expiry has no delay: Heimdall checks it at each request. |
| Elevation of privilege | A client loosens a rule that has no setting (D17) by a hidden field. | Heimdall binds only known fields. The code has no setting for D17 rules. |

## Health endpoints

Boundary: the orchestrator inside the deployment. `/health/live` and `/health/ready` run before tenant resolution and before the HTTPS check, because a probe calls the container IP over plain HTTP.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Information disclosure | A caller learns internal state, such as database errors, from a health response. | The body is one word: `Healthy` or `Unhealthy`. The reason stays on the server. |
| Information disclosure | The health endpoints are reachable from the internet over plain HTTP. | Set `Heimdall:Health:Port` to a management port. The endpoints then answer only on that port. Do not publish the port. |
| Denial of service | A database outage makes the orchestrator restart every server at once. | Liveness checks no dependency. Only readiness checks the database, so the orchestrator stops traffic but does not restart. |

## Telemetry

Boundary: the telemetry backend. OpenTelemetry sends traces and metrics over OTLP, only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. D7 applies to telemetry as it applies to logs.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Information disclosure | A trace holds a `state`, a code challenge, or a token from a query string. | Heimdall removes the `url.query` tag from every server span. No setting of the instrumentation can turn this off. A test checks it. |
| Information disclosure | A trace holds the `Authorization` header or a cookie. | The instrumentation records no request headers. A test sends a bearer token and checks that no span holds it. |
| Information disclosure | A trace holds parameter values of SQL statements. | Npgsql records the SQL text only. Every value in Heimdall's SQL is a parameter. |
| Denial of service | A caller sends many different `grant_type` values and creates unbounded metric tag values. | Every tag value comes from a fixed set. An unknown grant type is counted as `other`. No tag holds a client ID or a user. |

## Limits and lifetimes

These values are the platform defaults. A tenant or client can change a value only inside the limits (D15, D16). Change a default only with a recorded reason. Store each value in configuration, not in code.

Platform limits (D16). A tenant or client value must be inside these ranges. The values are in configuration (`Heimdall:PlatformLimits`). They are proposed starting values, not final. The server does not start if a minimum is zero or greater than its maximum.

| Setting | Minimum | Maximum |
|---|---|---|
| Session idle timeout | 5 minutes | 24 hours |
| Session absolute lifetime | 1 hour | 30 days |
| Access token lifetime | 1 minute | 60 minutes |
| Refresh idle timeout | 1 hour | 30 days |
| Refresh absolute lifetime | 1 day | 90 days |

| Item | Value | Note |
|---|---|---|
| Code lifetime | 5 minutes | Single-use. |
| Access token lifetime | 5 minutes | D8. |
| Refresh token family, absolute lifetime | 30 days | Rotation does not extend it. |
| Refresh token family, idle timeout | 7 days | Rotation does not extend it beyond the absolute lifetime. |
| Login session, idle timeout | 30 minutes | |
| Login session, absolute lifetime | 12 hours | |
| JWKS cache lifetime (`max-age`) | 10 minutes | Configuration: `Heimdall:SigningKeys:JwksCacheLifetime`. Discovery uses the same `max-age`. |
| Server key cache lifetime | 1 minute | A key, tenant, or client change on one server reaches every other server within this time. The changing server applies it at once. |
| Publish wait | 11 minutes | A new key waits the JWKS cache lifetime plus the server key cache lifetime before it signs. |
| Key rotation interval | 90 days | The job creates the next key one publish wait before this time ends. Configuration: `Heimdall:SigningKeys:RotationInterval`. |
| Clock skew | 5 minutes | Resource servers allow this difference when they check `exp`. |
| Argon2id parameters | 64 MiB, 3 passes, 1 lane | Above the OWASP minimum (19 MiB, 2 passes). A sign-in upgrades an older hash. Configuration: `Heimdall:PasswordHashing`. |
| Concurrent password hashes | One for each CPU core | Requests wait up to 5 seconds for a slot, then fail fast. |
| Retired key overlap | 65 minutes | A retired key stays in the JWKS for the platform maximum access token lifetime (60 minutes) plus clock skew. |
| Purge job interval | 1 hour | Configuration: `Heimdall:Purge`. Also the batch size (1000) and the retentions below. |
| Retention of an ended family | 7 days | A reused token of a recent family still causes a revocation and an alert. |
| Retention of an expired code with no family | 24 hours | A replayed code still shows as redeemed. |
| Retention of an ended session | 7 days | For an investigation. |
| Rate limit, `/token` and `/revoke` failures | 60 each minute for each IP | Only failed requests count. An IP that reaches the limit gets 429 before any database work, also with the right secret. A backend's normal traffic from one IP never reaches it. |
| Rate limit, `/token` issuance | 300 each minute for each authenticated client | Only the client's own successful issuances count. A caller with a wrong secret cannot use up another client's budget. |
| Rate limit, login | 5 attempts each minute for each IP | Each attempt costs one Argon2id hash, so successes count too. The sign-in throttle for each account is a separate control. |
| Sign-in throttle for each account and source | 5 free failures, then 1 s doubling to 15 minutes | Configuration: `Heimdall:LoginThrottle`. A source with no failure for 24 hours starts again at zero. |
| Rate limit, `/authorize` | 120 requests each minute for each IP | Each request can store an authorization request. |

Decision (2026-10-19): the counters are in memory on each server. With N servers, a caller gets up to N times each limit. This still caps the CPU and database load of each server, which is the purpose. An IPv6 address counts as its /64 network. A refused request gets 429, `Retry-After`, and the error `temporarily_unavailable`. The values are in configuration (`Heimdall:RateLimits`). A shared IP address (for example, an office) can reach the login limit. Review the values with k6 results in Phase 4.

## Open items

- Choose the breached-password list for D14: a local list or the Have I Been Pwned range API (k-anonymity). Build it with registration and password change.
- Add tables for registration, email verification, password reset, and account recovery.
