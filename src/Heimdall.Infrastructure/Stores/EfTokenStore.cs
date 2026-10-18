using Heimdall.Application.Tokens;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfTokenStore : ITokenStore
{
    private readonly HeimdallDbContext _db;

    public EfTokenStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<IGrantTransaction> BeginTransactionAsync(CancellationToken cancellationToken) =>
        new Transaction(await _db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false));

    public async Task<AuthorizationCode?> RedeemCodeAsync(CodeRedemption redemption, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(redemption);
        var hash = redemption.CodeHash.ToArray();

        // docs/schema-design.md, "Redeem a code". One statement. Every binding is in the WHERE clause, so a code is
        // consumed only by the right client, with the right redirect URI and PKCE verifier. A concurrent request
        // waits on the row lock, then sees redeemed_at set and matches no row. The values are parameters (FromSql).
        var rows = await _db.AuthorizationCodes
            .FromSql($"""
                UPDATE authorization_codes
                SET    redeemed_at = {redemption.Now}, family_id = {redemption.FamilyId}
                WHERE  tenant_id = {redemption.TenantId} AND code_hash = {hash}
                  AND  client_pk = {redemption.ClientPk}
                  AND  redirect_uri = {redemption.RedirectUri}
                  AND  code_challenge = {redemption.CodeChallenge}
                  AND  redeemed_at IS NULL AND expires_at > {redemption.Now}
                RETURNING *
                """)
            .IgnoreQueryFilters() // The tenant condition is in the statement. A filter would wrap it in a SELECT.
            .AsNoTracking()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return rows.SingleOrDefault();
    }

    public Task<AuthorizationCode?> FindCodeAsync(Guid tenantId, TokenHash codeHash, CancellationToken cancellationToken) =>
        _db.AuthorizationCodes.AsNoTracking()
            .SingleOrDefaultAsync(c => c.TenantId == tenantId && c.CodeHash == codeHash, cancellationToken);

    public async Task<RefreshToken?> UseRefreshTokenAsync(RefreshRotation rotation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rotation);
        var hash = rotation.TokenHash.ToArray();

        // docs/schema-design.md, "Rotate a refresh token". One statement. The family conditions are in it too: the
        // calling client must own the family, and the family must be unrevoked and inside both limits. A token sent by
        // another client matches no row, so it cannot burn the real client's token.
        var rows = await _db.RefreshTokens
            .FromSql($"""
                UPDATE refresh_tokens AS t
                SET    used_at = {rotation.Now}
                FROM   token_families AS f
                WHERE  t.tenant_id = {rotation.TenantId} AND t.token_hash = {hash} AND t.used_at IS NULL
                  AND  f.tenant_id = t.tenant_id AND f.id = t.family_id
                  AND  f.client_pk = {rotation.ClientPk}
                  AND  f.revoked_at IS NULL
                  AND  f.idle_expires_at > {rotation.Now} AND f.absolute_expires_at > {rotation.Now}
                RETURNING t.*
                """)
            .IgnoreQueryFilters()
            .AsNoTracking()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return rows.SingleOrDefault();
    }

    public Task<RefreshToken?> FindRefreshTokenAsync(Guid tenantId, TokenHash tokenHash, CancellationToken cancellationToken) =>
        _db.RefreshTokens.AsNoTracking()
            .SingleOrDefaultAsync(t => t.TenantId == tenantId && t.Hash == tokenHash, cancellationToken);

    public Task<TokenFamily?> FindFamilyAsync(Guid tenantId, Guid familyId, CancellationToken cancellationToken) =>
        _db.TokenFamilies.AsNoTracking()
            .SingleOrDefaultAsync(f => f.TenantId == tenantId && f.Id == familyId, cancellationToken);

    public async Task CompleteRotationAsync(
        RefreshToken used,
        RefreshToken replacement,
        TimeSpan idleTimeout,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(used);
        ArgumentNullException.ThrowIfNull(replacement);

        _db.RefreshTokens.Add(replacement);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await _db.Database.ExecuteSqlAsync(
            $"UPDATE refresh_tokens SET replaced_by_id = {replacement.Id} WHERE tenant_id = {used.TenantId} AND id = {used.Id}",
            cancellationToken).ConfigureAwait(false);

        // The idle limit moves forward but never passes the absolute limit (TokenFamily.ExtendIdle, as one statement).
        var idleUntil = now + idleTimeout;
        await _db.Database.ExecuteSqlAsync(
            $"""
            UPDATE token_families
            SET    idle_expires_at = LEAST({idleUntil}, absolute_expires_at)
            WHERE  tenant_id = {used.TenantId} AND id = {used.FamilyId}
            """,
            cancellationToken).ConfigureAwait(false);
    }

    public void AddFamily(TokenFamily family) => _db.TokenFamilies.Add(family);

    public void AddRefreshToken(RefreshToken token) => _db.RefreshTokens.Add(token);

    public Task SaveChangesAsync(CancellationToken cancellationToken) => _db.SaveChangesAsync(cancellationToken);

    public async Task<bool> RevokeFamilyAsync(
        Guid tenantId,
        Guid familyId,
        FamilyRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        // docs/schema-design.md, "Revoke a family": the recorded statement, as written there. It is idempotent, so the
        // first reason stays. The caller must not run it inside a transaction that it then rolls back.
        var reasonText = SnakeCaseEnumConverter<FamilyRevocationReason>.Write(reason);
        var changed = await _db.Database.ExecuteSqlAsync(
            $"""
            UPDATE token_families
            SET    revoked_at = {now}, revoked_reason = {reasonText}
            WHERE  tenant_id = {tenantId} AND id = {familyId} AND revoked_at IS NULL
            """,
            cancellationToken).ConfigureAwait(false);
        return changed == 1;
    }

    private sealed class Transaction : IGrantTransaction
    {
        private readonly IDbContextTransaction _inner;

        public Transaction(IDbContextTransaction inner)
        {
            _inner = inner;
        }

        public Task CommitAsync(CancellationToken cancellationToken) => _inner.CommitAsync(cancellationToken);

        // Without a commit, disposing rolls back.
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
