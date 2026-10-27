using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Authorization;

/// <summary>A stored pushed request (RFC 9126, section 2.2): the reference for <c>/authorize</c> and its lifetime.</summary>
public sealed record PushedRequest(string RequestUri, int ExpiresIn);

/// <summary>
/// The authorization endpoint: authorization code with PKCE (RFC 6749 section 4.1, RFC 7636, OAuth 2.1, RFC 9700),
/// and pushed authorization requests (RFC 9126, D40 to D43). It checks the request, stores it, and issues a code when
/// a valid session exists.
/// </summary>
/// <remarks>
/// The order of checks matters. Until <c>client_id</c> and <c>redirect_uri</c> are proven valid, an error is shown by
/// Heimdall and never redirected: a redirect to an unchecked URI is an open redirect. After that, errors go to the
/// client's registered redirect URI. <c>/authorize</c> and <c>/par</c> run the same checks, so a pushed request can
/// never pass a rule that a browser request fails.
/// </remarks>
public sealed class AuthorizationService
{
    /// <summary>RFC 9126, section 2.2: the URN form of a <c>request_uri</c>. 256 random bits follow it.</summary>
    public const string RequestUriPrefix = "urn:ietf:params:oauth:request_uri:";

    private static readonly string[] SupportedPrompts = ["none", "login"];

    private readonly IClientStore _clients;
    private readonly IAuthorizationStore _store;
    private readonly SessionService _sessions;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public AuthorizationService(
        IClientStore clients,
        IAuthorizationStore store,
        SessionService sessions,
        IAuditLog audit,
        TimeProvider time)
    {
        _clients = clients;
        _store = store;
        _sessions = sessions;
        _audit = audit;
        _time = time;
    }

    /// <param name="parameters">The query parameters. The endpoint already refused repeated parameters.</param>
    /// <param name="sessionId">The session cookie, or null.</param>
    public async Task<AuthorizeOutcome> AuthorizeAsync(
        RequestContext context,
        IReadOnlyDictionary<string, string> parameters,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(parameters);

        string? Get(string name) => parameters.TryGetValue(name, out var value) && value.Length > 0 ? value : null;

        // 1. The client. Errors here are never redirected.
        if (context.Tenant.Status != TenantStatus.Active)
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "tenant suspended");
        }

        if (Get("client_id") is not { } clientId)
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "client_id missing");
        }

        var client = await _clients.FindAsync(context.Tenant.Id, clientId, cancellationToken).ConfigureAwait(false);
        if (client is null || client.Status != ClientStatus.Active)
        {
            return new AuthorizeErrorPage(OAuthError.InvalidClientCode, client is null ? "unknown client" : $"client status {client.Status}");
        }

        // D42: a pushed request carries every other parameter. RFC 9126, section 4: the server uses only the pushed
        // values, so the parameters in the browser's address change nothing.
        if (Get("request_uri") is { } requestUri)
        {
            return await ContinuePushedAsync(context, client, requestUri, sessionId, cancellationToken).ConfigureAwait(false);
        }

        var checkedRequest = Check(context, client, Get, null);
        if (checkedRequest.Outcome is { } refused)
        {
            return refused;
        }

        var (request, promptNone) = (checkedRequest.Request!, checkedRequest.Request!.PromptNone);

        // D43: this client sends its requests only through PAR.
        if (client.RequirePushedAuthorizationRequests)
        {
            return ErrorRedirect(context, request.RedirectUri, request.State, OAuthError.InvalidRequestCode, "client requires pushed authorization requests");
        }

        // The request is stored only when Heimdall must show a page (sign-in or consent). A signed-in user gets the code
        // at once, and prompt=none never shows a page, so both need no stored request.
        return await ContinueAsync(context, client, request, stored: false, sessionId, promptNone, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /oauth/v1/par</c> (RFC 9126, D40, D41). The caller is the authenticated client. Heimdall runs every check
    /// of <c>/authorize</c>, stores the request for <see cref="AuthorizationRequest.PushedLifetime"/>, and returns a
    /// reference that only this client can use, once.
    /// </summary>
    /// <param name="parameters">The form parameters. The endpoint already refused repeated parameters.</param>
    /// <param name="proofKeyThumbprint">The key of the request's checked DPoP proof (RFC 9449, section 10.1), or null.</param>
    public async Task<Result<PushedRequest>> PushAsync(
        RequestContext context,
        Client client,
        IReadOnlyDictionary<string, string> parameters,
        string? proofKeyThumbprint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(parameters);

        string? Get(string name) => parameters.TryGetValue(name, out var value) && value.Length > 0 ? value : null;

        if (context.Tenant.Status != TenantStatus.Active)
        {
            return Result.Failure<PushedRequest>(OAuthError.InvalidClient("tenant suspended"));
        }

        // RFC 9126, section 2.1: a pushed request cannot point to another pushed request.
        if (Get("request_uri") is not null)
        {
            return Result.Failure<PushedRequest>(OAuthError.InvalidRequest("request_uri in a pushed request"));
        }

        // The client_id in the body, when present, must name the authenticated client (RFC 9126, section 2.1).
        if (Get("client_id") is { } clientId && !string.Equals(clientId, client.ClientId, StringComparison.Ordinal))
        {
            return Result.Failure<PushedRequest>(OAuthError.InvalidRequest("client_id differs from the authenticated client"));
        }

        // RFC 9449, section 10.1: a proof at PAR binds the code like dpop_jkt. With both, they must name the same key.
        var dpopKey = Get("dpop_jkt");
        if (proofKeyThumbprint is not null && dpopKey is not null && !string.Equals(proofKeyThumbprint, dpopKey, StringComparison.Ordinal))
        {
            return Result.Failure<PushedRequest>(OAuthError.InvalidDpopProof("DPoP proof key differs from dpop_jkt"));
        }

        var requestUri = RequestUriPrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var checkedRequest = Check(context, client, Get, TokenHash.Compute(requestUri), proofKeyThumbprint);
        if (checkedRequest.Outcome is { } refused)
        {
            // The client called Heimdall directly, so the error goes back in the response, never to a redirect.
            return Result.Failure<PushedRequest>(ToError(refused));
        }

        _store.AddRequest(checkedRequest.Request!);
        await _store.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return Result.Success(new PushedRequest(requestUri, (int)AuthorizationRequest.PushedLifetime.TotalSeconds));
    }

    /// <summary>
    /// Continues a stored request after the login (or consent) page. The browser sends only the request ID, so Heimdall
    /// returns only to what it stored and checked.
    /// </summary>
    public async Task<AuthorizeOutcome> ResumeAsync(
        RequestContext context,
        string? requestId,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!Guid.TryParse(requestId, out var id))
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "request_id malformed");
        }

        var request = await _store.FindRequestAsync(context.Tenant.Id, id, cancellationToken).ConfigureAwait(false);

        // A pushed request that /authorize has not taken yet is not resumable: only its request_uri starts it (D42).
        if (request is null || request.RequestUriHash is not null || request.IsExpired(_time.GetUtcNow()))
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, request is { RequestUriHash: null } ? "request expired" : "request unknown or used");
        }

        // Check the client again: an admin can disable it or remove the redirect URI while the user signs in.
        var client = await _clients.FindByPkAsync(context.Tenant.Id, request.ClientPk, cancellationToken).ConfigureAwait(false);
        if (client is not { Status: ClientStatus.Active } || !client.IsRedirectUriAllowed(request.RedirectUri))
        {
            return new AuthorizeErrorPage(OAuthError.InvalidClientCode, "client changed during sign-in");
        }

        return await ContinueAsync(context, client, request, stored: true, sessionId, promptNone: false, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// D42: <c>/authorize</c> with a <c>request_uri</c>. One conditional statement takes the pushed request, so a second
    /// use of the same value finds nothing. A <c>request_uri</c> that is unknown, used, expired, or of another client gets
    /// Heimdall's error page: Heimdall cannot trust a redirect URI that it cannot find.
    /// </summary>
    private async Task<AuthorizeOutcome> ContinuePushedAsync(
        RequestContext context,
        Client client,
        string requestUri,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        if (!requestUri.StartsWith(RequestUriPrefix, StringComparison.Ordinal) || requestUri.Length > 128)
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "request_uri malformed");
        }

        var request = await _store.TakePushedRequestAsync(context.Tenant.Id, TokenHash.Compute(requestUri), client.Id, _time.GetUtcNow(), cancellationToken)
            .ConfigureAwait(false);
        if (request is null)
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "request_uri unknown, used, expired, or of another client");
        }

        // The client can lose the redirect URI in the minute after the push.
        if (!client.IsRedirectUriAllowed(request.RedirectUri))
        {
            return new AuthorizeErrorPage(OAuthError.InvalidClientCode, "redirect_uri removed after the push");
        }

        return await ContinueAsync(context, client, request, stored: true, sessionId, request.PromptNone, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>The result of the checks: a refusal, or the checked request (not stored yet).</summary>
    private readonly record struct CheckedRequest(AuthorizeOutcome? Outcome, AuthorizationRequest? Request);

    /// <summary>
    /// Every check of an authorization request after the client is known. <c>/authorize</c> and <c>/par</c> share it.
    /// </summary>
    /// <param name="requestUriHash">For a pushed request, the hash of its new <c>request_uri</c>.</param>
    /// <param name="proofKeyThumbprint">
    /// For a pushed request with a DPoP proof, its key. It binds like dpop_jkt. A browser request never has one.
    /// </param>
    private CheckedRequest Check(
        RequestContext context,
        Client client,
        Func<string, string?> get,
        TokenHash? requestUriHash,
        string? proofKeyThumbprint = null)
    {
        string redirectUri;
        if (get("redirect_uri") is { } requested)
        {
            if (!client.IsRedirectUriAllowed(requested))
            {
                return new(new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "redirect_uri not registered (exact match)"), null);
            }

            redirectUri = requested;
        }
        else if (client.RedirectUris.Count == 1)
        {
            // RFC 6749, section 3.1.2.3: with one registered URI, the parameter may be left out.
            redirectUri = client.RedirectUris[0];
        }
        else
        {
            return new(new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "redirect_uri missing"), null);
        }

        // 2. From here on, errors go back to the client's registered redirect URI.
        var state = get("state");
        CheckedRequest Fail(string error, string reason) => new(ErrorRedirect(context, redirectUri, state, error, reason), null);

        if (state?.Length > AuthorizationRequest.MaxClientValueLength)
        {
            // Do not echo an oversized state back.
            return new(ErrorRedirect(context, redirectUri, null, OAuthError.InvalidRequestCode, "state too long"), null);
        }

        if (get("response_type") != "code")
        {
            return Fail("unsupported_response_type", "response_type is not code");
        }

        if (get("response_mode") is { } responseMode && responseMode != "query")
        {
            return Fail(OAuthError.InvalidRequestCode, "response_mode not supported");
        }

        if (get("request") is not null)
        {
            return Fail("request_not_supported", "request object");
        }

        if (!client.IsGrantAllowed(GrantType.AuthorizationCode))
        {
            return Fail(OAuthError.UnauthorizedClientCode, "authorization_code not allowed");
        }

        // D2: S256 for every client. A missing method would mean "plain" (RFC 7636), so it is refused too.
        if (get("code_challenge_method") != "S256")
        {
            return Fail(OAuthError.InvalidRequestCode, "code_challenge_method is not S256");
        }

        var codeChallenge = get("code_challenge");
        if (!Pkce.IsValidChallenge(codeChallenge))
        {
            return Fail(OAuthError.InvalidRequestCode, "code_challenge malformed or missing");
        }

        var scopes = ScopeParser.Parse(get("scope"));
        if (scopes is null || scopes.Count == 0)
        {
            return Fail(OAuthError.InvalidScopeCode, "scope malformed or missing");
        }

        // Refuse, do not reduce: a client that asks for too much has a configuration error.
        if (client.FilterAllowedScopes(scopes).Count != scopes.Count)
        {
            return Fail(OAuthError.InvalidScopeCode, "scope not allowed for client");
        }

        if (scopes.Contains("offline_access", StringComparer.Ordinal) && !client.RefreshEnabled)
        {
            return Fail(OAuthError.InvalidScopeCode, "offline_access without the refresh_token grant");
        }

        var prompts = (get("prompt") ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (prompts.Any(p => !SupportedPrompts.Contains(p, StringComparer.Ordinal)) || prompts.Length > 1)
        {
            // OpenID Connect: "none" with any other value is an error. Other values are not supported yet.
            return Fail(OAuthError.InvalidRequestCode, "prompt not supported");
        }

        TimeSpan? maxAge = null;
        if (get("max_age") is { } maxAgeText)
        {
            if (!int.TryParse(maxAgeText, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                return Fail(OAuthError.InvalidRequestCode, "max_age malformed");
            }

            maxAge = TimeSpan.FromSeconds(seconds);
        }

        var nonce = get("nonce");
        if (nonce?.Length > AuthorizationRequest.MaxClientValueLength)
        {
            return Fail(OAuthError.InvalidRequestCode, "nonce too long");
        }

        // D27, RFC 9449 section 10: the thumbprint of the key that must redeem the code. At PAR, a proof gives it too.
        var dpopKeyThumbprint = get("dpop_jkt");
        if (dpopKeyThumbprint is not null && !KeyThumbprint.IsValid(dpopKeyThumbprint))
        {
            return Fail(OAuthError.InvalidRequestCode, "dpop_jkt malformed");
        }

        dpopKeyThumbprint ??= proofKeyThumbprint;

        return new(null, AuthorizationRequest.Create(
            Guid.CreateVersion7(),
            context.Tenant.Id,
            client.Id,
            redirectUri,
            string.Join(' ', scopes),
            state,
            nonce,
            codeChallenge!,
            forceLogin: prompts.Contains("login"),
            maxAge,
            _time.GetUtcNow(),
            dpopKeyThumbprint,
            promptNone: prompts.Contains("none"),
            requestUriHash));
    }

    /// <summary>
    /// A refusal of <see cref="Check"/> as an error of the PAR response. Its code is the code that the redirect or the
    /// error page would carry. The reason stays for the log.
    /// </summary>
    private static OAuthError ToError(AuthorizeOutcome refused) => refused switch
    {
        AuthorizeErrorPage page => new OAuthError(page.Error, page.Reason),
        AuthorizeRedirect redirect => new OAuthError(redirect.Parameters[0].Value, redirect.Reason ?? string.Empty),
        _ => throw new InvalidOperationException($"Unknown refusal {refused.GetType().Name}."),
    };

    /// <param name="stored">True when the request is already stored: a resume after the sign-in or consent page.</param>
    private async Task<AuthorizeOutcome> ContinueAsync(
        RequestContext context,
        Client client,
        AuthorizationRequest request,
        bool stored,
        string? sessionId,
        bool promptNone,
        CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var session = await _sessions.ValidateAsync(context, sessionId, cancellationToken).ConfigureAwait(false);
        if (session is null || !request.AcceptsSession(session.Session, now))
        {
            return promptNone
                ? ErrorRedirect(context, request.RedirectUri, request.State, "login_required", "prompt=none without a usable session")
                : await ShowPageAsync(request, stored, new AuthorizeLogin(request.Id), cancellationToken).ConfigureAwait(false);
        }

        if (client.RequireConsent)
        {
            // Persisted consent is a Phase 3 item. Until then, the user decides for each request on the consent page.
            if (promptNone)
            {
                return ErrorRedirect(context, request.RedirectUri, request.State, "consent_required", "client requires consent");
            }

            var decision = request.ConsentDecisionOf(session.User.Id);
            if (decision is null)
            {
                return await ShowPageAsync(request, stored, new AuthorizeConsent(request.Id), cancellationToken).ConfigureAwait(false);
            }

            if (decision == false)
            {
                // The request ends here, so a later resume cannot turn the denial into a code.
                _store.RemoveRequest(request);
                try
                {
                    await _store.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (ConcurrentUpdateException)
                {
                    return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "request already used");
                }

                return ErrorRedirect(context, request.RedirectUri, request.State, "access_denied", "user denied consent");
            }
        }

        // 256 random bits. The database stores only the hash (D3). The plain code appears only in this redirect.
        var code = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        var authorizationCode = AuthorizationCode.Create(
            Guid.CreateVersion7(),
            context.Tenant.Id,
            client.Id,
            session.User.Id,
            TokenHash.Compute(code),
            request.RedirectUri,
            request.Scope,
            request.CodeChallenge,
            request.Nonce,
            session.Session.AuthTime,
            now,
            session.Session.Sid,
            request.DpopKeyThumbprint);

        _store.AddCode(authorizationCode);
        if (stored)
        {
            _store.RemoveRequest(request);
        }

        try
        {
            await _store.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ConcurrentUpdateException)
        {
            // Another resume of the same request issued its code first. One request gives one code.
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "request already used");
        }

        await _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                AuditEventTypes.CodeIssued,
                context.CorrelationId,
                now,
                context.SourceIp,
                subjectUserId: session.User.Id,
                clientPk: client.Id,
                data: new Dictionary<string, string> { ["client_id"] = client.ClientId, ["scope"] = request.Scope }),
            cancellationToken).ConfigureAwait(false);

        var parameters = new List<KeyValuePair<string, string>> { new("code", code) };
        if (request.State is { } state)
        {
            parameters.Add(new("state", state));
        }

        parameters.Add(new("iss", context.Issuer));
        return new AuthorizeRedirect(request.RedirectUri, parameters);
    }

    /// <summary>Stores a new request, so the page can send the browser back to it by ID.</summary>
    private async Task<AuthorizeOutcome> ShowPageAsync(
        AuthorizationRequest request,
        bool stored,
        AuthorizeOutcome page,
        CancellationToken cancellationToken)
    {
        if (!stored)
        {
            _store.AddRequest(request);
            await _store.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return page;
    }

    private static AuthorizeRedirect ErrorRedirect(RequestContext context, string redirectUri, string? state, string error, string reason)
    {
        var parameters = new List<KeyValuePair<string, string>> { new("error", error) };
        if (state is not null)
        {
            parameters.Add(new("state", state));
        }

        // RFC 9207 (D9): iss on error responses too, so a client can detect a mix-up.
        parameters.Add(new("iss", context.Issuer));
        return new AuthorizeRedirect(redirectUri, parameters, reason);
    }
}
