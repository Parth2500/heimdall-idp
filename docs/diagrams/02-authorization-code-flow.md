# 02 Authorization code flow with PKCE

## Full flow

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant B as Browser
    participant C as Client
    participant H as Heimdall
    participant DB as PostgreSQL
    participant R as Resource server

    C->>C: Create code_verifier, compute code_challenge (S256)
    C->>B: Redirect to /authorize
    B->>H: GET /authorize (client_id, redirect_uri, scope, state, code_challenge)
    H->>DB: Load client, check redirect_uri (exact match), check scope
    alt No valid session
        H->>B: Show login page
        U->>B: Enter credentials
        B->>H: POST login
        H->>H: Argon2id check, new session ID, set cookie
    end
    alt Consent missing
        H->>B: Show consent page (data from stored request)
        U->>B: Approve
        B->>H: POST consent (anti-forgery token)
        H->>DB: Save consent
    end
    H->>DB: Insert code hash (expires in 5 minutes)
    H->>B: Redirect to redirect_uri (code, state, iss)
    B->>C: GET callback
    C->>H: POST /token (grant_type, code, code_verifier, redirect_uri, client auth)
    H->>DB: Atomic UPDATE: redeem code
    H->>H: Check PKCE, client, redirect_uri
    H->>DB: Insert family and first refresh token hash
    H->>C: access_token, id_token, refresh_token (no-store)
    C->>R: Request with access token
    R->>R: Verify signature with cached JWKS
    R->>C: Response
```

## Decisions made at /token

```mermaid
flowchart TD
    S(["POST /token"]) --> F{"Form body, no repeated parameters?"}
    F -- No --> E1["invalid_request"]
    F -- Yes --> CA{"Client authenticated or public?"}
    CA -- No --> E2["invalid_client"]
    CA -- Yes --> G{"Grant allowed for this client?"}
    G -- No --> E3["unauthorized_client"]
    G -- Yes --> GT{"grant_type"}
    GT -- authorization_code --> RC["Atomic UPDATE: redeem code"]
    GT -- refresh_token --> RT["See refresh diagram"]
    GT -- client_credentials --> SC["Check scope against AllowedScopes"]
    RC --> OK1{"One row returned?"}
    OK1 -- No --> RU{"Code exists and already redeemed?"}
    RU -- Yes --> REV["Revoke family from that code, audit event, alert"]
    RU -- No --> E4["invalid_grant"]
    REV --> E4
    OK1 -- Yes --> CB{"client_id, redirect_uri, PKCE verifier match?"}
    CB -- No --> E4
    CB -- Yes --> ISS["Issue tokens"]
    SC --> ISS
```

Every `invalid_grant` looks the same to the caller (D5). Only the audit log has the real reason.
