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

/// <summary>
/// The authorization endpoint: authorization code with PKCE (RFC 6749 section 4.1, RFC 7636, OAuth 2.1, RFC 9700).
/// It checks the request, stores it, and issues a code when a valid session exists.
/// </summary>
/// <remarks>
/// The order of checks matters. Until <c>client_id</c> and <c>redirect_uri</c> are proven valid, an error is shown by
/// Heimdall and never redirected: a redirect to an unchecked URI is an open redirect. After that, errors go to the
/// client's registered redirect URI.
/// </remarks>
public sealed class AuthorizationService
{
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

        // 1. The client and the redirect URI. Errors here are never redirected.
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

        string redirectUri;
        if (Get("redirect_uri") is { } requested)
        {
            if (!client.IsRedirectUriAllowed(requested))
            {
                return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "redirect_uri not registered (exact match)");
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
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "redirect_uri missing");
        }

        // 2. From here on, errors go back to the client's registered redirect URI.
        var state = Get("state");
        AuthorizeRedirect Fail(string error, string reason) => ErrorRedirect(context, redirectUri, state, error, reason);

        if (state?.Length > AuthorizationRequest.MaxClientValueLength)
        {
            // Do not echo an oversized state back.
            return ErrorRedirect(context, redirectUri, null, OAuthError.InvalidRequestCode, "state too long");
        }

        if (Get("response_type") != "code")
        {
            return Fail("unsupported_response_type", "response_type is not code");
        }

        if (Get("response_mode") is { } responseMode && responseMode != "query")
        {
            return Fail(OAuthError.InvalidRequestCode, "response_mode not supported");
        }

        if (Get("request") is not null)
        {
            return Fail("request_not_supported", "request object");
        }

        if (Get("request_uri") is not null)
        {
            // PAR (RFC 9126) is a Phase 2 item.
            return Fail("request_uri_not_supported", "request_uri");
        }

        if (!client.IsGrantAllowed(GrantType.AuthorizationCode))
        {
            return Fail(OAuthError.UnauthorizedClientCode, "authorization_code not allowed");
        }

        // D2: S256 for every client. A missing method would mean "plain" (RFC 7636), so it is refused too.
        if (Get("code_challenge_method") != "S256")
        {
            return Fail(OAuthError.InvalidRequestCode, "code_challenge_method is not S256");
        }

        var codeChallenge = Get("code_challenge");
        if (!Pkce.IsValidChallenge(codeChallenge))
        {
            return Fail(OAuthError.InvalidRequestCode, "code_challenge malformed or missing");
        }

        var scopes = ScopeParser.Parse(Get("scope"));
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

        var prompts = (Get("prompt") ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (prompts.Any(p => !SupportedPrompts.Contains(p, StringComparer.Ordinal)) || prompts.Length > 1)
        {
            // OpenID Connect: "none" with any other value is an error. Other values are not supported yet.
            return Fail(OAuthError.InvalidRequestCode, "prompt not supported");
        }

        TimeSpan? maxAge = null;
        if (Get("max_age") is { } maxAgeText)
        {
            if (!int.TryParse(maxAgeText, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                return Fail(OAuthError.InvalidRequestCode, "max_age malformed");
            }

            maxAge = TimeSpan.FromSeconds(seconds);
        }

        var nonce = Get("nonce");
        if (nonce?.Length > AuthorizationRequest.MaxClientValueLength)
        {
            return Fail(OAuthError.InvalidRequestCode, "nonce too long");
        }

        var now = _time.GetUtcNow();
        var request = AuthorizationRequest.Create(
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
            now);

        var promptNone = prompts.Contains("none");
        if (!promptNone)
        {
            // prompt=none never leaves Heimdall to show a page, so it needs no stored request.
            _store.AddRequest(request);
            await _store.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return await ContinueAsync(context, client, request, sessionId, promptNone, cancellationToken).ConfigureAwait(false);
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
        if (request is null || request.IsExpired(_time.GetUtcNow()))
        {
            return new AuthorizeErrorPage(OAuthError.InvalidRequestCode, request is null ? "request unknown or used" : "request expired");
        }

        // Check the client again: an admin can disable it or remove the redirect URI while the user signs in.
        var client = await _clients.FindByPkAsync(context.Tenant.Id, request.ClientPk, cancellationToken).ConfigureAwait(false);
        if (client is not { Status: ClientStatus.Active } || !client.IsRedirectUriAllowed(request.RedirectUri))
        {
            return new AuthorizeErrorPage(OAuthError.InvalidClientCode, "client changed during sign-in");
        }

        return await ContinueAsync(context, client, request, sessionId, promptNone: false, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AuthorizeOutcome> ContinueAsync(
        RequestContext context,
        Client client,
        AuthorizationRequest request,
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
                : new AuthorizeLogin(request.Id);
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
                return new AuthorizeConsent(request.Id);
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
            now);

        _store.AddCode(authorizationCode);
        if (!promptNone)
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
