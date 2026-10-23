using Heimdall.Domain.Common;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Tokens;

/// <summary>The inputs of the atomic code redemption. Every binding is part of the one conditional statement.</summary>
/// <param name="ClientPk">The authenticated client. A code issued to another client never matches (confused deputy).</param>
/// <param name="RedirectUri">Must equal the stored redirect URI exactly.</param>
/// <param name="CodeChallenge">BASE64URL(SHA256(code_verifier)). Must equal the stored challenge (PKCE S256).</param>
/// <param name="FamilyId">The new family that this redemption starts.</param>
/// <param name="DpopKeyThumbprint">
/// The key of the request's DPoP proof, or null. A code from a request with <c>dpop_jkt</c> matches only this key, so a
/// thief without the key cannot redeem the code, and cannot use it up either (D27).
/// </param>
public sealed record CodeRedemption(
    Guid TenantId,
    TokenHash CodeHash,
    Guid ClientPk,
    string RedirectUri,
    string CodeChallenge,
    Guid FamilyId,
    DateTimeOffset Now,
    string? DpopKeyThumbprint = null);

/// <summary>The inputs of the atomic refresh token rotation. Every binding is part of the one conditional statement.</summary>
/// <param name="ClientPk">The authenticated client. A token of another client's family never matches.</param>
/// <param name="DpopKeyThumbprint">
/// The key of the request's DPoP proof, or null. A bound family matches only this key, so a thief without the key
/// cannot use the token, and cannot use it up either (D24).
/// </param>
public sealed record RefreshRotation(Guid TenantId, TokenHash TokenHash, Guid ClientPk, DateTimeOffset Now, string? DpopKeyThumbprint = null);

/// <summary>A database transaction. Dispose without commit rolls back.</summary>
public interface IGrantTransaction : IAsyncDisposable
{
    Task CommitAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Codes, token families, and refresh tokens. The redemption and the revocation are single atomic statements
/// (docs/schema-design.md, "The atomic statements"). A check in application code, followed by an update, is not allowed.
/// </summary>
public interface ITokenStore
{
    Task<IGrantTransaction> BeginTransactionAsync(CancellationToken cancellationToken);

    /// <summary>
    /// One conditional UPDATE: it redeems the code only when it is unredeemed, unexpired, and every binding matches.
    /// Returns the code, or null when no row matched. A concurrent redemption waits on the row lock and then matches
    /// no row.
    /// </summary>
    Task<AuthorizationCode?> RedeemCodeAsync(CodeRedemption redemption, CancellationToken cancellationToken);

    /// <summary>Reads a code by hash, without a change. Used to explain a redemption that matched no row.</summary>
    Task<AuthorizationCode?> FindCodeAsync(Guid tenantId, TokenHash codeHash, CancellationToken cancellationToken);

    void AddFamily(TokenFamily family);

    void AddRefreshToken(RefreshToken token);

    Task SaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// One conditional UPDATE: it marks the token used only when it is unused, and its family belongs to the client,
    /// is not revoked, and is inside its idle and absolute limits. Returns the used token, or null when no row matched.
    /// A concurrent rotation of the same token waits on the row lock and then matches no row.
    /// </summary>
    Task<RefreshToken?> UseRefreshTokenAsync(RefreshRotation rotation, CancellationToken cancellationToken);

    /// <summary>Reads a refresh token by hash, without a change. Used to explain a rotation that matched no row.</summary>
    Task<RefreshToken?> FindRefreshTokenAsync(Guid tenantId, TokenHash tokenHash, CancellationToken cancellationToken);

    /// <summary>Reads a family, without a change.</summary>
    Task<TokenFamily?> FindFamilyAsync(Guid tenantId, Guid familyId, CancellationToken cancellationToken);

    /// <summary>
    /// In the rotation transaction: inserts the new token, links the used token to it (<c>replaced_by_id</c>), and moves
    /// the family's idle limit, never past its absolute limit.
    /// </summary>
    Task CompleteRotationAsync(
        RefreshToken used,
        RefreshToken replacement,
        TimeSpan idleTimeout,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>One conditional UPDATE. Returns true when this call revoked the family, false when it was already revoked.</summary>
    Task<bool> RevokeFamilyAsync(
        Guid tenantId,
        Guid familyId,
        FamilyRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken);
}
