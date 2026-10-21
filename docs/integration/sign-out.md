# Sign out

[Documentation home](../documentation.md)

Sign-out has three parts. Heimdall supports two of them today.

| Part | What ends | Supported |
|---|---|---|
| Your app's session | The user's session in your app. | Yes. Your app does it. |
| The refresh token family | Every refresh token from this sign-in. | Yes. Revoke it at `/revoke`. |
| The Heimdall session | The user's session at Heimdall, for every app. | Not yet. RP-initiated logout is planned. |

## Step 1: Revoke the refresh token

If your client has a refresh token, revoke it (RFC 7009):

```http
POST /oauth/v1/revoke HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded

token=8xLOxBtZp8...
&client_id=orders-web
```

A confidential client sends HTTP Basic instead of `client_id`.

- Revocation ends the **whole family**, including the newest refresh token.
- Heimdall returns `200` with an empty body for every well-formed request from an authenticated client. The response does not tell you if the token existed. This is RFC 7009 behavior.
- Heimdall ignores `token_type_hint`.
- Heimdall cannot revoke an access token. It stays valid until `exp` (5 minutes by default). Send an access token to `/revoke` and you get `200`, but nothing changes.
- A client can revoke only its own tokens. A token of another client gets `200` and nothing changes.

## Step 2: End your app's session

Delete your app's session and every token that it holds. In a browser app, clear the tokens from memory.

## The Heimdall session stays

Heimdall has no `end_session_endpoint` yet. After step 1 and step 2, the user's Heimdall session is still active. If the user clicks "Sign in" again, Heimdall can sign them in with no login page.

This matters on a shared computer. Until RP-initiated logout exists, use one of these options:

- Send `prompt=login` on the next sign-in. Heimdall then asks for credentials again, even with an active session.
- Tell the user to close the browser. The Heimdall session cookie has no expiry date, so the browser deletes it on close. Some browsers restore cookies when they restore the last session, so this option is not certain.

In all cases, Heimdall ends the session after its idle timeout (30 minutes by default) or its absolute lifetime (12 hours by default).
