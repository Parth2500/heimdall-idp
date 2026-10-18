using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;

namespace Heimdall.Application.Users;

/// <param name="User">The signed-in user, or null when the sign-in failed.</param>
public sealed record LoginResult(User? User)
{
    public static LoginResult Failed { get; } = new((User?)null);

    public bool Succeeded => User is not null;
}

/// <summary>
/// Checks an email and a password. Every failure looks the same to the caller: one generic result, and one Argon2id
/// verification on every path, so neither the answer nor the response time shows whether an account exists
/// (threat model, login, Spoofing). The real reason goes to the audit log only (D5).
/// </summary>
/// <remarks>
/// Throttling for each account and IP is a Phase 2 item. Heimdall never locks an account, because a lock lets an
/// attacker deny service to the real user.
/// </remarks>
public sealed class UserAuthenticator
{
    private readonly IUserStore _users;
    private readonly IPasswordHasher _hasher;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public UserAuthenticator(IUserStore users, IPasswordHasher hasher, IAuditLog audit, TimeProvider time)
    {
        _users = users;
        _hasher = hasher;
        _audit = audit;
        _time = time;
    }

    /// <exception cref="PasswordHasherBusyException">The server is at its hashing limit. Answer "try again later".</exception>
    public async Task<LoginResult> AuthenticateAsync(
        RequestContext context,
        string? email,
        string? password,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Malformed input is refused before the hash and is not audited: it reveals nothing about any account.
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrEmpty(password) || PasswordPolicy.IsTooLongToHash(password))
        {
            return LoginResult.Failed;
        }

        var user = await _users
            .FindByEmailAsync(context.Tenant.Id, User.NormalizeEmail(email), cancellationToken)
            .ConfigureAwait(false);

        // One verification on every path. A null hash verifies against a dummy and fails.
        var check = await _hasher.VerifyAsync(user?.PasswordHash, password, cancellationToken).ConfigureAwait(false);

        string? reason = null;
        if (user is null)
        {
            reason = "unknown user";
        }
        else if (!check.Verified)
        {
            reason = "wrong password";
        }
        else if (user.Status != UserStatus.Active)
        {
            // Checked after the hash, so a disabled account takes the same time as a wrong password.
            reason = "user disabled";
        }
        else if (context.Tenant.Status != TenantStatus.Active)
        {
            reason = "tenant suspended";
        }

        if (reason is not null)
        {
            await WriteAuditAsync(context, AuditEventTypes.LoginFailed, user?.Id, reason, cancellationToken).ConfigureAwait(false);
            return LoginResult.Failed;
        }

        if (check.NeedsRehash)
        {
            // The settings got stronger since this hash was made. The plain password is here only now, so upgrade now.
            user!.UpgradePasswordHash(await _hasher.HashAsync(password, cancellationToken).ConfigureAwait(false));
            await _users.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        await WriteAuditAsync(context, AuditEventTypes.LoginSucceeded, user!.Id, null, cancellationToken).ConfigureAwait(false);
        return new LoginResult(user);
    }

    private Task WriteAuditAsync(
        RequestContext context,
        string type,
        Guid? userId,
        string? reason,
        CancellationToken cancellationToken) =>
        _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                type,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: userId,
                data: reason is null ? null : new Dictionary<string, string> { ["reason"] = reason }),
            cancellationToken);
}
