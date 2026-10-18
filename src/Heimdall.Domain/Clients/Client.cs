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
    private readonly List<GrantType> _allowedGrantTypes;
    private readonly List<string> _allowedScopes;
    private readonly List<string> _redirectUris;

    private Client(
        Guid id,
        Guid tenantId,
        string clientId,
        string name,
        ClientType type,
        List<GrantType> allowedGrantTypes,
        List<string> allowedScopes,
        List<string> redirectUris,
        bool requireConsent,
        ClientTokenOverrides overrides,
        DateTimeOffset createdAt)
    {
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
        DateTimeOffset now)
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

        return new Client(
            id,
            tenantId,
            normalizedClientId,
            Guard.NotBlank(name, nameof(name)),
            type,
            grants,
            scopes,
            uris,
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
