using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;

namespace Heimdall.Domain.Clients;

public enum ClientType
{
    Public,
    Confidential,
}

public enum TokenEndpointAuthMethod
{
    None,
    ClientSecretBasic,
}

public enum GrantType
{
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

public enum ClientStatus
{
    /// <summary>Registered but not yet approved by an admin. A pending client cannot get tokens.</summary>
    Pending,
    Active,
    Disabled,
}

/// <summary>
/// A client application. The rules in this class protect every client from a weak configuration (D17).
/// </summary>
public sealed class Client
{
    // Not readonly: EF Core writes these fields when it loads a client.
    private List<GrantType> _allowedGrantTypes = [];
    private List<string> _allowedScopes = [];
    private List<string> _redirectUris = [];
    private List<string> _allowedAudiences = [];

#pragma warning disable CS8618 // EF Core sets the properties after it calls this constructor.
    private Client()
    {
    }
#pragma warning restore CS8618

    private Client(
        Guid id,
        Guid tenantId,
        string clientId,
        string name,
        ClientType type,
        List<GrantType> allowedGrantTypes,
        List<string> allowedScopes,
        List<string> redirectUris,
        List<string> allowedAudiences,
        bool requireConsent,
        ClientTokenOverrides overrides,
        DateTimeOffset createdAt)
    {
        _allowedAudiences = allowedAudiences;
        Id = id;
        TenantId = tenantId;
        ClientId = clientId;
        Name = name;
        Type = type;
        TokenEndpointAuthMethod = type == ClientType.Public
            ? TokenEndpointAuthMethod.None
            : TokenEndpointAuthMethod.ClientSecretBasic;
        _allowedGrantTypes = allowedGrantTypes;
        _allowedScopes = allowedScopes;
        _redirectUris = redirectUris;
        RequireConsent = requireConsent;
        TokenOverrides = overrides;
        Status = ClientStatus.Pending;
        CreatedAt = createdAt;
    }

    public Guid Id { get; }

    public Guid TenantId { get; }

    /// <summary>The public identifier. It is unique within a tenant.</summary>
    public string ClientId { get; }

    public string Name { get; private set; }

    public ClientType Type { get; }

    /// <summary>Derived from <see cref="Type"/>, so an invalid combination cannot exist.</summary>
    public TokenEndpointAuthMethod TokenEndpointAuthMethod { get; }

    public IReadOnlyList<GrantType> AllowedGrantTypes => _allowedGrantTypes;

    public IReadOnlyList<string> AllowedScopes => _allowedScopes;

    public IReadOnlyList<string> RedirectUris => _redirectUris;

    /// <summary>The resource servers this client may get tokens for. Each one is a value for the <c>aud</c> claim (D22).</summary>
    public IReadOnlyList<string> AllowedAudiences => _allowedAudiences;

    public bool RequireConsent { get; private set; }

    public ClientTokenOverrides TokenOverrides { get; private set; }

    public ClientStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; }

    /// <summary>A client can refresh only if it has the refresh_token grant.</summary>
    public bool RefreshEnabled => _allowedGrantTypes.Contains(GrantType.RefreshToken);

    public static Client Create(
        Guid id,
        Guid tenantId,
        string clientId,
        string name,
        ClientType type,
        IEnumerable<GrantType> allowedGrantTypes,
        IEnumerable<string> allowedScopes,
        IEnumerable<string> redirectUris,
        bool requireConsent,
        ClientTokenOverrides? overrides,
        DateTimeOffset now,
        IEnumerable<string>? allowedAudiences = null)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        ArgumentNullException.ThrowIfNull(allowedGrantTypes);
        ArgumentNullException.ThrowIfNull(allowedScopes);
        ArgumentNullException.ThrowIfNull(redirectUris);

        var normalizedClientId = Guard.NotBlank(clientId, nameof(clientId));
        if (normalizedClientId.Any(char.IsWhiteSpace))
        {
            throw new DomainException("The client_id must not contain white space.");
        }

        var grants = allowedGrantTypes.Distinct().ToList();
        if (grants.Count == 0)
        {
            throw new DomainException("A client needs at least one grant type.");
        }

        // client_credentials has no user and no PKCE. The secret is the only defense (see /token, Spoofing).
        if (grants.Contains(GrantType.ClientCredentials) && type != ClientType.Confidential)
        {
            throw new DomainException("Only a confidential client can use the client_credentials grant.");
        }

        // A refresh token is only issued from a code redemption.
        if (grants.Contains(GrantType.RefreshToken) && !grants.Contains(GrantType.AuthorizationCode))
        {
            throw new DomainException("The refresh_token grant needs the authorization_code grant.");
        }

        var scopes = ScopeRules.Normalize(allowedScopes);

        var uris = redirectUris.Select(RedirectUriRules.Validate).Distinct(StringComparer.Ordinal).ToList();
        if (grants.Contains(GrantType.AuthorizationCode) && uris.Count == 0)
        {
            throw new DomainException("A client with the authorization_code grant needs a redirect URI.");
        }

        var audiences = (allowedAudiences ?? []).Select(AudienceRules.Validate).Distinct(StringComparer.Ordinal).ToList();
        if (grants.Contains(GrantType.ClientCredentials) && audiences.Count == 0)
        {
            // A client_credentials token is only useful at a resource server, so it must name one.
            throw new DomainException("A client with the client_credentials grant needs at least one audience.");
        }

        return new Client(
            id,
            tenantId,
            normalizedClientId,
            Guard.NotBlank(name, nameof(name)),
            type,
            grants,
            scopes,
            uris,
            audiences,
            requireConsent,
            overrides ?? ClientTokenOverrides.None,
            now);
    }

    /// <summary>
    /// Compares by exact string match. No normalization, no wildcards, no prefix match (RFC 9700).
    /// </summary>
    public bool IsRedirectUriAllowed(string? redirectUri) =>
        redirectUri is not null && _redirectUris.Contains(redirectUri, StringComparer.Ordinal);

    public bool IsGrantAllowed(GrantType grantType) => _allowedGrantTypes.Contains(grantType);

    /// <summary>
    /// Chooses the <c>aud</c> value for a token (RFC 8707, D22). A requested resource must match an allowed
    /// audience exactly. With no request, the only allowed audience is the default. Returns null when no
    /// audience fits; the caller then returns <c>invalid_target</c>.
    /// </summary>
    public string? ResolveAudience(string? requestedResource)
    {
        if (requestedResource is null)
        {
            return _allowedAudiences.Count == 1 ? _allowedAudiences[0] : null;
        }

        return _allowedAudiences.Contains(requestedResource, StringComparer.Ordinal) ? requestedResource : null;
    }

    /// <summary>
    /// Chooses the <c>aud</c> value for a token that a user's grant issues (D22). Every such token may name the tenant's
    /// userinfo endpoint, because the user's sign-in allows the client to read the user's claims there. A client with
    /// no registered audience gets the userinfo endpoint as its default. Other rules are those of
    /// <see cref="ResolveAudience"/>.
    /// </summary>
    /// <param name="userInfoAudience">The tenant's userinfo endpoint URL.</param>
    public string? ResolveUserAudience(string? requestedResource, string userInfoAudience)
    {
        Guard.NotBlank(userInfoAudience, nameof(userInfoAudience));

        if (requestedResource is null)
        {
            return _allowedAudiences.Count == 0 ? userInfoAudience : ResolveAudience(null);
        }

        return string.Equals(requestedResource, userInfoAudience, StringComparison.Ordinal)
            ? userInfoAudience
            : ResolveAudience(requestedResource);
    }

    /// <summary>Returns the scopes that the client may receive from the requested ones.</summary>
    public IReadOnlyList<string> FilterAllowedScopes(IEnumerable<string> requested) =>
        requested.Where(s => _allowedScopes.Contains(s, StringComparer.Ordinal)).Distinct(StringComparer.Ordinal).ToList();

    /// <summary>Uses the client value when it exists, and the tenant value if not (D15).</summary>
    public TokenLifetimes ResolveLifetimes(TenantSettings tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        var lifetimes = new TokenLifetimes(
            TokenOverrides.AccessToken ?? tenant.AccessToken,
            TokenOverrides.RefreshIdle ?? tenant.RefreshIdle,
            TokenOverrides.RefreshAbsolute ?? tenant.RefreshAbsolute);

        if (lifetimes.RefreshIdle > lifetimes.RefreshAbsolute)
        {
            throw new DomainException("The refresh idle timeout must not be longer than the absolute lifetime.");
        }

        return lifetimes;
    }

    public void UpdateTokenOverrides(ClientTokenOverrides overrides)
    {
        ArgumentNullException.ThrowIfNull(overrides);
        TokenOverrides = overrides;
    }

    public void Approve()
    {
        if (Status == ClientStatus.Pending)
        {
            Status = ClientStatus.Active;
        }
    }

    public void Disable() => Status = ClientStatus.Disabled;
}
