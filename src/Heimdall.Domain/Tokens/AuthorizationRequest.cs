using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;

namespace Heimdall.Domain.Tokens;

/// <summary>
/// A checked <c>/authorize</c> request, stored while the user signs in. The login page and the resume step refer to it
/// by its ID only, so the browser cannot change the client, the redirect URI, the scope, or the PKCE challenge
/// (threat model, login, Tampering). After sign-in, Heimdall returns only to this stored request: there is no
/// free-form return URL (open redirect).
/// </summary>
public sealed class AuthorizationRequest
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    /// <summary>The longest <c>state</c> or <c>nonce</c> value. Both are client values that Heimdall stores and echoes.</summary>
    public const int MaxClientValueLength = 512;

#pragma warning disable CS8618 // EF Core sets the properties after it calls this constructor.
    private AuthorizationRequest()
    {
    }
#pragma warning restore CS8618

    private AuthorizationRequest(
        Guid id,
        Guid tenantId,
        Guid clientPk,
        string redirectUri,
        string scope,
        string? state,
        string? nonce,
        string codeChallenge,
        bool forceLogin,
        TimeSpan? maxAge,
        DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        ClientPk = clientPk;
        RedirectUri = redirectUri;
        Scope = scope;
        State = state;
        Nonce = nonce;
        CodeChallenge = codeChallenge;
        ForceLogin = forceLogin;
        MaxAge = maxAge;
        CreatedAt = createdAt;
        ExpiresAt = createdAt + Lifetime;
    }

    public Guid Id { get; }

    public Guid TenantId { get; }

    public Guid ClientPk { get; }

    /// <summary>The redirect URI after the exact-match check against the client's list.</summary>
    public string RedirectUri { get; }

    /// <summary>The checked scope, space-separated.</summary>
    public string Scope { get; }

    public string? State { get; }

    public string? Nonce { get; }

    public string CodeChallenge { get; }

    /// <summary><c>prompt=login</c>: only a sign-in after this request was created counts.</summary>
    public bool ForceLogin { get; }

    /// <summary>The OpenID Connect <c>max_age</c>: the longest time since the user last entered credentials.</summary>
    public TimeSpan? MaxAge { get; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    /// <summary>The user who decided on the consent page, or null. A decision counts only for this user.</summary>
    public Guid? ConsentUserId { get; private set; }

    /// <summary>The decision of <see cref="ConsentUserId"/>: true to approve, false to deny, null when none.</summary>
    public bool? ConsentApproved { get; private set; }

    public static AuthorizationRequest Create(
        Guid id,
        Guid tenantId,
        Guid clientPk,
        string redirectUri,
        string scope,
        string? state,
        string? nonce,
        string codeChallenge,
        bool forceLogin,
        TimeSpan? maxAge,
        DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(clientPk, nameof(clientPk));

        if (!Pkce.IsValidChallenge(codeChallenge))
        {
            throw new DomainException("The code challenge must be a BASE64URL SHA-256 value (S256).");
        }

        if (state?.Length > MaxClientValueLength || nonce?.Length > MaxClientValueLength)
        {
            throw new DomainException($"The state and nonce must have at most {MaxClientValueLength} characters.");
        }

        if (maxAge < TimeSpan.Zero)
        {
            throw new DomainException("The max_age must not be negative.");
        }

        return new AuthorizationRequest(
            id,
            tenantId,
            clientPk,
            Guard.NotBlank(redirectUri, nameof(redirectUri)),
            Guard.NotBlank(scope, nameof(scope)),
            string.IsNullOrEmpty(state) ? null : state,
            string.IsNullOrEmpty(nonce) ? null : nonce,
            codeChallenge,
            forceLogin,
            maxAge,
            now);
    }

    public bool IsExpired(DateTimeOffset now) => now >= ExpiresAt;

    /// <summary>
    /// Records the consent decision of the signed-in user for this one request. A later decision replaces it. Persisted
    /// consent across requests is a Phase 3 item.
    /// </summary>
    public void DecideConsent(Guid userId, bool approved)
    {
        Guard.NotEmpty(userId, nameof(userId));
        ConsentUserId = userId;
        ConsentApproved = approved;
    }

    /// <summary>
    /// The decision of this user, or null when this user has not decided. The decision of another user never counts:
    /// when a second user signs in on the same browser, that user must decide again.
    /// </summary>
    public bool? ConsentDecisionOf(Guid userId) => ConsentUserId == userId ? ConsentApproved : null;

    /// <summary>
    /// True when a valid session satisfies this request: a sign-in after the request for <c>prompt=login</c>, and a
    /// sign-in within <see cref="MaxAge"/> when the client set it.
    /// </summary>
    public bool AcceptsSession(Session session, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(session);

        // Strictly after: a sign-in at the same instant as the request could be the old one. Ask again.
        if (ForceLogin && session.AuthTime <= CreatedAt)
        {
            return false;
        }

        return MaxAge is not { } maxAge || session.IsAuthenticatedWithin(maxAge, now);
    }
}
