using Heimdall.Application.Alerts;
using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Common;
using Heimdall.Domain.Tokens;

namespace Heimdall.UnitTests.Application;

/// <summary>
/// A test fake of the token store. Each conditional statement of <c>EfTokenStore</c> has the same conditions here, so
/// the grants can run without a database. The integration tests check the SQL itself.
/// </summary>
/// <remarks>
/// The SQL statements change columns directly, not through Domain methods. This fake does the same with
/// <see cref="Set"/>. A transaction records an undo step for each change, and disposal without a commit runs them.
/// </remarks>
internal sealed class InMemoryTokenStore : ITokenStore
{
    private readonly List<TokenFamily> _unsavedFamilies = [];
    private readonly List<RefreshToken> _unsavedTokens = [];
    // The undo steps of the open transaction, or null outside a transaction.
    private List<Action>? _undo;

    public List<AuthorizationCode> Codes { get; } = [];

    public List<TokenFamily> Families { get; } = [];

    public List<RefreshToken> RefreshTokens { get; } = [];

    public int Commits { get; private set; }

    public int Rollbacks { get; private set; }

    public Task<IGrantTransaction> BeginTransactionAsync(CancellationToken cancellationToken)
    {
        _undo = [];
        return Task.FromResult<IGrantTransaction>(new FakeTransaction(this, _undo));
    }

    public Task<AuthorizationCode?> RedeemCodeAsync(CodeRedemption redemption, CancellationToken cancellationToken)
    {
        var code = Codes.SingleOrDefault(c =>
            c.TenantId == redemption.TenantId
            && c.CodeHash == redemption.CodeHash
            && c.ClientPk == redemption.ClientPk
            && c.RedirectUri == redemption.RedirectUri
            && c.CodeChallenge == redemption.CodeChallenge
            && (c.DpopKeyThumbprint is null || c.DpopKeyThumbprint == redemption.DpopKeyThumbprint)
            && c.RedeemedAt is null
            && c.ExpiresAt > redemption.Now);
        if (code is not null)
        {
            Change(code, nameof(AuthorizationCode.RedeemedAt), redemption.Now);
            Change(code, nameof(AuthorizationCode.FamilyId), redemption.FamilyId);
        }

        return Task.FromResult(code);
    }

    public Task<AuthorizationCode?> FindCodeAsync(Guid tenantId, TokenHash codeHash, CancellationToken cancellationToken) =>
        Task.FromResult(Codes.SingleOrDefault(c => c.TenantId == tenantId && c.CodeHash == codeHash));

    public void AddFamily(TokenFamily family) => _unsavedFamilies.Add(family);

    public void AddRefreshToken(RefreshToken token) => _unsavedTokens.Add(token);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        foreach (var family in _unsavedFamilies)
        {
            Families.Add(family);
            _undo?.Add(() => Families.Remove(family));
        }

        foreach (var token in _unsavedTokens)
        {
            RefreshTokens.Add(token);
            _undo?.Add(() => RefreshTokens.Remove(token));
        }

        _unsavedFamilies.Clear();
        _unsavedTokens.Clear();
        return Task.CompletedTask;
    }

    public Task<RefreshToken?> UseRefreshTokenAsync(RefreshRotation rotation, CancellationToken cancellationToken)
    {
        var token = RefreshTokens.SingleOrDefault(t =>
            t.TenantId == rotation.TenantId
            && t.Hash == rotation.TokenHash
            && t.UsedAt is null
            && Families.Any(f =>
                f.TenantId == t.TenantId
                && f.Id == t.FamilyId
                && f.ClientPk == rotation.ClientPk
                && f.RevokedAt is null
                && f.IdleExpiresAt > rotation.Now
                && f.AbsoluteExpiresAt > rotation.Now
                && (f.DpopKeyThumbprint is null || f.DpopKeyThumbprint == rotation.DpopKeyThumbprint)));
        if (token is not null)
        {
            Change(token, nameof(RefreshToken.UsedAt), rotation.Now);
        }

        return Task.FromResult(token);
    }

    public Task<RefreshToken?> FindRefreshTokenAsync(Guid tenantId, TokenHash tokenHash, CancellationToken cancellationToken) =>
        Task.FromResult(RefreshTokens.SingleOrDefault(t => t.TenantId == tenantId && t.Hash == tokenHash));

    public Task<TokenFamily?> FindFamilyAsync(Guid tenantId, Guid familyId, CancellationToken cancellationToken) =>
        Task.FromResult(Families.SingleOrDefault(f => f.TenantId == tenantId && f.Id == familyId));

    public Task CompleteRotationAsync(
        RefreshToken used,
        RefreshToken replacement,
        TimeSpan idleTimeout,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        RefreshTokens.Add(replacement);
        _undo?.Add(() => RefreshTokens.Remove(replacement));
        Change(used, nameof(RefreshToken.ReplacedById), (Guid?)replacement.Id);

        var family = Families.Single(f => f.TenantId == used.TenantId && f.Id == used.FamilyId);
        var idleUntil = now + idleTimeout;
        Change(family, nameof(TokenFamily.IdleExpiresAt), idleUntil < family.AbsoluteExpiresAt ? idleUntil : family.AbsoluteExpiresAt);
        return Task.CompletedTask;
    }

    public Task<bool> RevokeFamilyAsync(
        Guid tenantId,
        Guid familyId,
        FamilyRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var family = Families.SingleOrDefault(f => f.TenantId == tenantId && f.Id == familyId && f.RevokedAt is null);
        if (family is null)
        {
            return Task.FromResult(false);
        }

        Change(family, nameof(TokenFamily.RevokedAt), (DateTimeOffset?)now);
        Change(family, nameof(TokenFamily.RevocationReason), (FamilyRevocationReason?)reason);
        return Task.FromResult(true);
    }

    /// <summary>Sets a property as an UPDATE statement would, past the Domain methods.</summary>
    public static void Set<T>(object entity, string property, T value) =>
        entity.GetType().GetProperty(property)!.SetValue(entity, value);

    private void Change<T>(object entity, string property, T value)
    {
        var old = entity.GetType().GetProperty(property)!.GetValue(entity);
        Set(entity, property, value);
        _undo?.Add(() => Set(entity, property, old));
    }

    private sealed class FakeTransaction : IGrantTransaction
    {
        private readonly InMemoryTokenStore _store;
        private readonly List<Action> _undo;
        private bool _committed;

        public FakeTransaction(InMemoryTokenStore store, List<Action> undo)
        {
            _store = store;
            _undo = undo;
        }

        public Task CommitAsync(CancellationToken cancellationToken)
        {
            _committed = true;
            _store.Commits++;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            if (!_committed)
            {
                for (var i = _undo.Count - 1; i >= 0; i--)
                {
                    _undo[i]();
                }

                _store._unsavedFamilies.Clear();
                _store._unsavedTokens.Clear();
                _store.Rollbacks++;
            }

            _store._undo = null;
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed class RecordingTokenSigner : ITokenSigner
{
    public List<(Guid TenantId, AccessTokenClaims Claims)> Signed { get; } = [];

    public List<(Guid TenantId, IdTokenClaims Claims)> SignedIdTokens { get; } = [];

    /// <summary>When true, signing fails as if the tenant had no active key.</summary>
    public bool Unavailable { get; set; }

    public Task<string> SignAccessTokenAsync(Guid tenantId, AccessTokenClaims claims, CancellationToken cancellationToken)
    {
        if (Unavailable)
        {
            throw new SigningKeyUnavailableException(tenantId);
        }

        Signed.Add((tenantId, claims));
        return Task.FromResult("signed." + claims.JwtId);
    }

    public Task<string> SignIdTokenAsync(Guid tenantId, IdTokenClaims claims, CancellationToken cancellationToken)
    {
        if (Unavailable)
        {
            throw new SigningKeyUnavailableException(tenantId);
        }

        SignedIdTokens.Add((tenantId, claims));
        return Task.FromResult("id." + claims.Subject);
    }
}

internal sealed class RecordingSecurityAlerts : ISecurityAlerts
{
    public List<(string Type, Guid TenantId, IReadOnlyDictionary<string, string> Data)> Raised { get; } = [];

    public void Raise(string type, Guid tenantId, IReadOnlyDictionary<string, string> data) => Raised.Add((type, tenantId, data));
}

/// <summary>
/// A test fake of the proof validator. A proof "proof:&lt;thumbprint&gt;:&lt;jti&gt;" passes with that key and
/// <c>jti</c>. Any other text fails. The real rules are in DpopProofValidatorTests.
/// </summary>
internal sealed class FakeDpopProofValidator : Heimdall.Application.Dpop.IDpopProofValidator
{
    public List<(string Proof, Heimdall.Application.Dpop.DpopRequest Request)> Checked { get; } = [];

    public static string Proof(string keyThumbprint, string jti = "jti-1") => $"proof:{keyThumbprint}:{jti}";

    public Heimdall.Application.Common.Result<Heimdall.Application.Dpop.DpopProof> Validate(string proof, Heimdall.Application.Dpop.DpopRequest request)
    {
        Checked.Add((proof, request));
        var parts = proof.Split(':');
        return parts is ["proof", var key, var jti]
            ? Heimdall.Application.Common.Result.Success(new Heimdall.Application.Dpop.DpopProof(key, jti, DateTimeOffset.UnixEpoch))
            : Heimdall.Application.Common.Result.Failure<Heimdall.Application.Dpop.DpopProof>(Heimdall.Application.Common.OAuthError.InvalidDpopProof("fake refused"));
    }
}

/// <summary>A test fake of the replay store: the same tenant, key, and jti work once.</summary>
internal sealed class InMemoryDpopReplayStore : Heimdall.Application.Dpop.IDpopReplayStore
{
    public HashSet<(Guid Tenant, string Key, string Jti)> Seen { get; } = [];

    public Task<bool> TryUseAsync(Guid tenantId, Heimdall.Application.Dpop.DpopProof proof, CancellationToken cancellationToken) =>
        Task.FromResult(Seen.Add((tenantId, proof.KeyThumbprint, proof.Jti)));
}
