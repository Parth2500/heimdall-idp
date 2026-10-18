# Heimdall Threat Model (Phase 0)

Method: STRIDE for each trust boundary. References: RFC 6749, RFC 7636 (PKCE), RFC 7009 (revocation), RFC 9700 (OAuth Security BCP), RFC 9207 (issuer identification), OAuth 2.1 draft.

Writing rules are in `CLAUDE.md`. They follow ASD-STE100 style, applied by hand.

## Glossary

Each term has one meaning in this document. Do not use a synonym.

| Term | Meaning |
|---|---|
| Heimdall | This identity provider. It is also the issuer. |
| Client | An application that asks Heimdall for tokens. |
| Public client | A client that cannot keep a secret (single-page app, mobile app). |
| Confidential client | A client that can keep a secret (server application). |
| Resource server | An API that accepts Heimdall access tokens. |
| Subject | The user that an access token or ID token identifies. |
| Code | An authorization code. It is single-use and short-lived. |
| Redeem | To exchange a code for tokens at `/token`. |
| Access token | A short-lived JWT that a client sends to a resource server. |
| Refresh token | An opaque token that a client exchanges for new tokens. |
| Family | All refresh tokens that come from one code redemption. Each family has one `TokenFamilyId`. |
| Rotate | To replace a refresh token with a new one each time the client uses it. |
| Reuse | A second use of a code or refresh token that is already used. |
| Revoke | To make a token or family permanently invalid. |
| Bearer | A token that gives access to anyone who holds it. |
| PKCE | Proof Key for Code Exchange. It binds a code to the client that asked for it. |
| Verifier, challenge | The `code_verifier` is a secret from the client. The `code_challenge` is its SHA-256 hash. |
| JWKS | The public key set that Heimdall publishes. Resource servers use it to check signatures. |
| `kid` | The key identifier. It tells a verifier which key in the JWKS signed a token. |
| Hash | A one-way digest of a secret. Heimdall stores hashes, not secrets. |
| Throttle | To slow or limit requests. It does not lock out the caller. |
| Audit log | An append-only record of security events. |

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

## `GET /oauth/v1/authorize` (worked example)
| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | A rogue client registers a redirect URI that looks like a real one. | Heimdall compares redirect URIs by exact match. It allows no wildcards. An admin must approve each client registration. |
| Tampering | An attacker changes the `code_challenge` on the network. | TLS (D1). PKCE also stops a man-in-the-middle from using a stolen code. |
| Repudiation | A user says they did not grant consent. | Heimdall stores a timestamped consent record for each user, client, and scope. |
| Information disclosure | A code leaks through browser history, the referrer header, or logs. | A code is single-use and expires after 5 minutes. Heimdall never writes a full code to a log (D7). |
| Denial of service | A flood of `/authorize` requests uses all database resources. | Rate limit for each IP and each `client_id`. |
| Elevation of privilege | A client requests more scope than it is allowed. | Heimdall checks the requested scope on the server against the `AllowedScopes` of the client. |

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
| **Repudiation** | A client or user denies a redemption or issuance. After a theft, no evidence exists. | Heimdall writes one audit record for each issuance, redemption, rejection, and family revocation. The record has: timestamp, `client_id`, subject, grant type, result, source IP, correlation ID. The table is insert-only. The application role has no update or delete right. An immutable store is a Phase 3 item. |
| **Information disclosure** | A browser or proxy caches tokens or secrets. | `no-store` (D6). |
| Information disclosure | Secrets, codes, verifiers, or tokens appear in logs, traces, or exception messages. | D7. Request logging for this route excludes the body and the `Authorization` header. |
| Information disclosure | A database leak (backup, SQL injection) gives an attacker live credentials. | Heimdall stores hashes only (D3). It uses parameterized queries only (EF Core). |
| Information disclosure | An error response shows why a code failed (expired, used, or wrong client). | D5. Only the audit log has the reason. |
| Information disclosure | An access token holds more claims than the resource server needs. | The token holds only `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, and `client_id`. Personal data goes only in the ID token and `/userinfo`, and only if the scope allows it. |
| **Denial of service** | A flood of `/token` requests uses all database connections or CPU. | Rate limit for each IP and each `client_id`. Body size limit. Short timeouts. Heimdall rejects malformed requests before any database call. |
| Denial of service | An attacker sends wrong secrets on purpose to lock out a victim client. | Heimdall throttles. It does not lock. The real client stays able to authenticate. |
| Denial of service | Many requests redeem one code at the same time and hold row locks. | One atomic statement: `UPDATE ... WHERE redeemed_at IS NULL AND expires_at > now() RETURNING ...`. A losing request gets zero rows and returns at once. No lock is held for long. |
| **Elevation of privilege** | Two requests redeem the same code at the same time (race). Both get tokens. | The atomic conditional update above, with a unique index on `CodeHash`. A check in application code, followed by an update, is not allowed. |
| Elevation of privilege | An attacker replays a captured code after redemption. | The conditional update affects zero rows on a redeemed code. Heimdall treats this as reuse. In one transaction, it revokes the family that came from that code. It writes an audit event and raises an alert. It does not revoke all sessions of the user and client pair. |
| Elevation of privilege | A client requests a grant it may not use, such as `client_credentials` from a public client. | Each client has an `AllowedGrantTypes` list, checked here. Only confidential clients can use `client_credentials`. |
| Elevation of privilege | A client requests more scope at `/token` than the user approved. | The issued scope is the overlap of the code's approved scope and the client's `AllowedScopes`. Refresh can only reduce scope. |
| Elevation of privilege | A client redeems a code with a different `redirect_uri` or `client_id`. | Heimdall compares with the stored values by exact match. A mismatch returns `invalid_grant` (D5). |

## Refresh flow

Boundary: B2. A refresh token is opaque and single-use. It belongs to a family. The family starts at the code redemption.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker uses a stolen refresh token. | Each use returns a new refresh token and marks the old one as used (`ReplacedByTokenHash`). Reuse of a used token revokes the whole family at once, in the same transaction as the check. Confidential clients also authenticate. DPoP protects public clients in Phase 2. |
| Spoofing | A client presents a token that Heimdall issued to a different client. | The stored `client_id` must equal the calling client. |
| Tampering | The real client and an attacker present the same token at the same time. Two retries can also cause this. | Rotation is one atomic conditional update on `used_at IS NULL`. One caller wins. Heimdall treats the other caller as reuse. |
| Tampering | A client asks for more scope on refresh. | The requested scope must be a subset of the original grant. |
| Repudiation | No record shows who rotated a token or why a family ended. | Heimdall writes an audit event for each rotation, reuse detection, and revocation. It includes the family ID and the correlation ID. |
| Information disclosure | An attacker reads tokens from the database. | Heimdall stores SHA-256 hashes only (D3). The plain token appears once, in the response (D6). |
| Denial of service | An attacker with a stolen token triggers reuse on purpose, so the victim loses the session. | Accepted. The victim signs in again. This failure is safer than leaving a live session to the thief. Alerts make the pattern visible. |
| Denial of service | A real client retries after it loses a response and triggers reuse detection. | Decision: no grace window. A grace window reopens the race that reuse detection closes. A client must save the new token before it uses it. The integration guide states this. |
| Denial of service | Expired tokens and families fill the database. | A scheduled job deletes expired families. Indexes exist on `TokenFamilyId` and `TokenHash`. |
| Elevation of privilege | A client rotates forever and keeps a session without end. | The family has an absolute lifetime (for example, 30 days) and an idle timeout. Rotation does not extend either one. A user or admin revocation ends the whole family. |
| Elevation of privilege | A refresh succeeds after the user account is disabled or consent is removed. | On each refresh, Heimdall checks that the user is active and consent exists. If not, it returns `invalid_grant` and revokes the family. |

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
| Elevation of privilege | An attacker steals a signing key and creates valid tokens. | Emergency procedure: remove the key's `kid` from the JWKS at once. Tokens that this key signed stop working. This cost is accepted. Then add a new key. Key Vault or KMS keeps private keys non-exportable. |
| Elevation of privilege | Rotation breaks live tokens. Or a new key signs before caches know it. | Publish the new key in the JWKS at least one cache lifetime before it signs a token. Keep the old `kid` listed until its last token expires (token lifetime plus clock skew). |

## `POST /oauth/v1/revoke` (RFC 7009)

Boundary: B2. The endpoint revokes a refresh token with its family, or an access token.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker revokes the tokens of another client. | Confidential clients authenticate as at `/token` (D4, D5). The stored `client_id` of the token must equal the caller. On a mismatch, Heimdall revokes nothing, returns `200`, and writes an audit event. |
| Spoofing | A public client revokes with a stolen token. | The refresh token is already a bearer secret. Whoever holds it can revoke it. Revocation only helps the real owner. |
| Tampering | A request repeats a parameter or sends credentials in the query string. | The same rules as `/token`: form body only, no repeated parameters. |
| Repudiation | A user or client disputes a revocation. | Heimdall writes an audit event for each revocation. It records token type, family ID, client, caller IP, and correlation ID. |
| Information disclosure | The response shows whether a token existed or was valid. | Heimdall returns `200` for an unknown, expired, revoked, or foreign token (RFC 7009, section 2.2). Only a malformed request or failed client authentication gets an error. |
| Denial of service | An attacker sends many revocations to flood or lock rows. | Rate limit for each IP and each `client_id`. Revocation is one indexed update on `TokenFamilyId`. |
| Elevation of privilege | A revoked refresh token family continues to work. | Heimdall revokes the whole family in one transaction. This includes the newest refresh token. |
| Elevation of privilege | A revoked access token still works until it expires. | Accepted risk. Access tokens are stateless JWTs with a lifetime of 5 minutes (D8). Version 1 has no denylist. Phase 2 adds introspection (RFC 7662) for resource servers that need immediate revocation. |

## `GET /oauth/v1/userinfo`

Boundary: B2 and B5. The endpoint needs a bearer access token. It returns the claims of the subject.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker sends a forged token, or a token for a different issuer or audience. | Heimdall checks the signature with `RS256` only (D8). It checks `iss`, `aud`, and `exp`. It rejects `client_credentials` tokens, because they have no subject. |
| Spoofing | An attacker replays a stolen access token. | The short lifetime (D8). DPoP adds sender-constraining in Phase 2. |
| Tampering | A client sends the token in the query string or form body. Logs and caches keep it. | Heimdall accepts the `Authorization: Bearer` header only. |
| Repudiation | A party disputes access to user data. | Heimdall writes an audit event for each call: `sub`, `client_id`, released scopes, correlation ID. It does not log claim values. |
| Information disclosure | The response gives more claims than the scope allows. | Heimdall releases only the claims that the granted scopes allow (`profile`, `email`, and so on). The `sub` always equals the `sub` of the ID token. |
| Information disclosure | A browser or proxy caches the response. | `Cache-Control: no-store`. CORS allows only registered client origins. It never uses `*`. |
| Information disclosure | An error response shows details. | Heimdall returns a generic `invalid_token` error with no reason (D5). |
| Denial of service | A flood of calls causes one database read for each call. | Rate limit for each subject and each IP. Heimdall loads claims by primary key. A short-lived cache of user claims is optional. |
| Elevation of privilege | A disabled or deleted user, or removed consent, still gets data until the token expires. | Heimdall loads the user on each call. It rejects an inactive user or missing consent. This check is stricter than a JWT check alone. |
| Elevation of privilege | A token with only the `openid` scope reads profile claims. | Heimdall maps scopes to claims on the server. |

## Open items

- Choose the key store for local development (database or file). Design the Key Vault and KMS abstraction in `Application`.
- Set the numbers: code lifetime (5 minutes), refresh idle timeout, refresh absolute lifetime, rate limits.
- Add user login and the session cookie to the model. This is boundary B1. It is not covered yet.
- Next document: the EF Core schema (entities, constraints, indexes).
