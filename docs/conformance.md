# OpenID conformance results

This page records the results of the OpenID Foundation conformance suite against Heimdall (issue #20). The setup and the commands are in [tools/conformance/README.md](../tools/conformance/README.md).

## Setup

- Date of the run: 2026-10-28.
- Suite: `gitlab.com/openid/conformance-suite`, commit `23353b36957d6466010de767c812d2c91ed37638`, run locally with Podman.
- Heimdall: the development tenant `acme.localhost`, two static confidential clients (`conformance-1`, `conformance-2`) with `client_secret_basic`.
- Patch: Heimdall requires PKCE `S256` from every client (D2). The suite's OpenID Connect modules send no PKCE, so a local patch adds it. The owner chose this on 2026-10-28.
- Local configuration: the login rate limit is 1000 each minute for this run. The suite signs in many times from one address, and the default limit (5 each minute for each IP) times the modules out.

Because of the patch, these results are not an official OpenID certification. A certification needs the unchanged suite.

## Results

| Plan | Passed | Review | Warning | Skipped | Failed |
|---|---|---|---|---|---|
| `oidcc-config-certification-test-plan` | 1 | 0 | 0 | 0 | 0 |
| `oidcc-basic-certification-test-plan` (discovery, static client) | 22 | 4 | 3 | 5 | 1 |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 2 | 0 | 0 | 0 | 0 |
| `oidcc-rp-initiated-logout-certification-test-plan` | 3 | 8 | 0 | 0 | 0 |

A module in "Review" passed its automatic checks. It waits for a person to check a screenshot of what the user saw, for example the second sign-in page of `prompt=login`, or Heimdall's error page for an unregistered redirect URI. The driver uploads the screenshots. Nobody has reviewed them in the suite yet.

## Expected results that are not a pass

Each row below follows a recorded decision or a feature that is not built yet. None of them is a defect.

| Module | Result | Reason |
|---|---|---|
| `oidcc-server-client-secret-post` | Failed | Heimdall supports only `client_secret_basic` for confidential clients (D10). Discovery lists only that method. The suite still runs the module and finds no client for `client_secret_post`. |
| `oidcc-userinfo-post-body` | Warning | Heimdall accepts the access token only in the `Authorization` header. RFC 6750, section 2.2, makes the form body method optional. A token in a body or a URL ends up in logs (threat model, `/userinfo`). |
| `oidcc-ensure-request-with-acr-values-succeeds` | Warning | Heimdall issues no `acr` claim. It has one authentication method (a password). The claim comes with multi-factor authentication through WebAuthn (Phase 3, #31). |
| `oidcc-claims-essential` | Warning | Heimdall stores no `name` for a user, so `/userinfo` cannot release it. Profile claims come with registration (Phase 3, #28). |
| `oidcc-scope-profile`, `-address`, `-phone`, `-all` | Skipped | Discovery does not list these scopes (`scopes_supported`), so the suite skips them. |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | Skipped | Heimdall does not support request objects. Discovery does not list `request_parameter_supported`, so its default value `false` applies (OpenID Connect Discovery, section 3). A pushed authorization request (RFC 9126, D40) protects the parameters instead. |

## Defects that the suite found

The suite found these defects. Each is fixed, with tests.

| Module | Defect | Fix |
|---|---|---|
| `oidcc-discovery-endpoint-verification` | Discovery did not list `scopes_supported` and `claims_supported`. | Discovery lists the scopes and claims that Heimdall itself knows. |
| `oidcc-refresh-token` | `/authorize` refused `prompt=consent`. A client that asks for `offline_access` sends it (OpenID Connect Core, section 11). | Heimdall accepts `prompt=consent` and shows the consent page, also for a client that does not require consent. `prompt` values combine, except `none` with another value. |
| `oidcc-codereuse-30seconds` | After a code reuse, `/userinfo` still accepted the access token from the first redemption until it expired. | `/userinfo` reads the token's family with its user in one query. A revoked family makes the token invalid at once (D44). |

The first runs also timed out three modules (`oidcc-scope-email`, `oidcc-prompt-none-logged-in`, `oidcc-login-hint`). The cause was the login rate limit, not a defect. They pass with the local configuration above.
