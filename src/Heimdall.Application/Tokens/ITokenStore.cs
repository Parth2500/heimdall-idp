using Heimdall.Domain.Common;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Tokens;

/// <summary>The inputs of the atomic code redemption. Every binding is part of the one conditional statement.</summary>
/// <param name="ClientPk">The authenticated client. A code issued to another client never matches (confused deputy).</param>
/// <param name="RedirectUri">Must equal the stored redirect URI exactly.</param>
/// <param name="CodeChallenge">BASE64URL(SHA256(code_verifier)). Must equal the stored challenge (PKCE S256).</param>
/// <param name="FamilyId">The new family that this redemption starts.</param>
public sealed record CodeRedemption(
    Guid TenantId,
    TokenHash CodeHash,
    Guid ClientPk,
    string RedirectUri,
    string CodeChallenge,
    Guid FamilyId,
    DateTimeOffset Now);

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

    /// <summary>One conditional UPDATE. Returns true when this call revoked the family, false when it was already revoked.</summary>
    Task<bool> RevokeFamilyAsync(
        Guid tenantId,
        Guid familyId,
        FamilyRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken);
}
