# Heimdall documentation

Heimdall is an OAuth 2.1 and OpenID Connect identity provider. This documentation tells you how to connect your application to Heimdall.

Heimdall follows the standards. You do not need a Heimdall library. Use a certified OpenID Connect library for your platform, and set it up as these pages describe.

## Who this documentation is for

| You build | Start here |
|---|---|
| A browser app (Angular, React, or another single-page app) | [Sign in users](integration/sign-in-users.md), then the [Angular SPA recipe](integration/recipes/angular-spa.md). |
| A server app that signs users in (Node.js, ASP.NET Core) | [Sign in users](integration/sign-in-users.md), then the [Node.js recipe](integration/recipes/node-server.md) or the [ASP.NET Core recipe](integration/recipes/aspnet-core.md). |
| A service that calls an API with no user | [Service-to-service tokens](integration/service-to-service.md). |
| An API that accepts Heimdall access tokens | [Validate access tokens](integration/validate-access-tokens.md). |

## Quick start

1. Ask the Heimdall operator to register your client. See [Register a client](integration/register-a-client.md).
2. Get the issuer URL of your tenant, for example `https://acme.example.com`.
3. Give the issuer URL to your OpenID Connect library. The library reads the rest from discovery: `<issuer>/.well-known/openid-configuration`.
4. Use the authorization code flow with PKCE (`S256`). Heimdall refuses every other flow for user sign-in.
5. Check the `iss` parameter in the authorization response, and check the ID token. Most libraries do both for you.

## Guides

- [Concepts](integration/concepts.md): tenants, issuers, client types, and the tokens that Heimdall issues.
- [Register a client](integration/register-a-client.md): what to give the operator, and the rules for redirect URIs.
- [Sign in users](integration/sign-in-users.md): the authorization code flow with PKCE, step by step.
- [Refresh tokens](integration/refresh-tokens.md): rotation, reuse detection, and how to store refresh tokens.
- [DPoP](integration/dpop.md): bind tokens to a key that your client holds (RFC 9449). Supported at `/authorize` and `/token`; `/userinfo` and discovery are in progress.
- [Service-to-service tokens](integration/service-to-service.md): the `client_credentials` grant.
- [Validate access tokens](integration/validate-access-tokens.md): the checks that a resource server must do.
- [Sign out](integration/sign-out.md): revocation, and what Heimdall does not support yet.
- [Errors and rate limits](integration/errors-and-limits.md): error codes, status codes, and what to do for each.

## Reference

- [Endpoint reference](integration/endpoint-reference.md): every endpoint, its parameters, and its responses.

## Recipes

Each recipe uses a client that signs in with Heimdall today, or it says that it is not tested yet.

- [Angular single-page app](integration/recipes/angular-spa.md) with `angular-auth-oidc-client`. Source: the demo SPA in `ui/projects/demo`.
- [Node.js server](integration/recipes/node-server.md) with `openid-client` and `jose`. Source: the Huginn chat app.
- [ASP.NET Core](integration/recipes/aspnet-core.md) with the Microsoft OpenID Connect and JWT bearer handlers. Not yet tested against Heimdall.

## What Heimdall supports

| Feature | Status |
|---|---|
| Authorization code flow with PKCE (`S256` only) | Supported. PKCE is required for every client. |
| Refresh tokens with rotation | Supported. Reuse revokes the family. |
| `client_credentials` grant | Supported for confidential clients. |
| Discovery and JWKS | Supported. |
| `iss` in the authorization response (RFC 9207) | Supported. |
| Resource indicators (`resource`, RFC 8707) | Supported at `/token`. |
| Userinfo endpoint | Supported. It releases `sub`, `email`, and `email_verified`. |
| Token revocation (RFC 7009) | Supported for refresh tokens. |
| DPoP (RFC 9449) | Supported at `/authorize` (`dpop_jkt`) and at `/token`: bound codes, bound access tokens, and bound refresh tokens for public clients. Not yet at `/userinfo` or in discovery. |
| Client authentication | `client_secret_basic` for confidential clients. `none` for public clients. |
| Implicit flow, hybrid flow, password grant | Not supported, by design (OAuth 2.1, RFC 9700). |
| `response_mode=form_post` or `fragment` | Not supported. Heimdall returns the code in the query. |
| `client_secret_post`, `private_key_jwt` | Not supported. |
| Request objects (`request`) and PAR (`request_uri`) | Not supported yet. PAR is planned. |
| DPoP (RFC 9449) | Not supported yet. It is planned. |
| RP-initiated logout (`end_session_endpoint`) | Not supported yet. See [Sign out](integration/sign-out.md). |
| Dynamic client registration | Not supported. The operator registers clients. |
| Token introspection (RFC 7662) | Not supported yet. It is planned. |
| Silent renew in a hidden iframe | Not supported, by design. Heimdall pages refuse to load in a frame. Use refresh tokens. |

Heimdall puts only what it supports in the discovery document. If a feature is not in discovery, do not use it.

## Report a security problem

Do not open a public issue. Follow [SECURITY.md](../SECURITY.md).
