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
/// Failures are throttled for each account and source (<see cref="LoginThrottle"/>). Heimdall never locks an account,
/// because a lock lets an attacker deny service to the real user: an attacker's failures slow only the attacker's
/// source. While a wait runs, the password is not checked at all, so guessing makes no progress. The attempt still
/// costs one dummy verification and gets the same answer, so a throttled account looks like any failed sign-in.
/// </remarks>
public sealed class UserAuthenticator
{
    private readonly IUserStore _users;
    private readonly IPasswordHasher _hasher;
    private readonly ILoginThrottleStore _throttle;
    private readonly LoginThrottleOptions _throttleOptions;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public UserAuthenticator(
        IUserStore users,
        IPasswordHasher hasher,
        ILoginThrottleStore throttle,
        LoginThrottleOptions throttleOptions,
        IAuditLog audit,
        TimeProvider time)
    {
        _users = users;
        _hasher = hasher;
        _throttle = throttle;
        _throttleOptions = throttleOptions;
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

        var now = _time.GetUtcNow();
        var source = SourceKeys.For(context.SourceIp);

        // The read runs for an unknown user too (with an ID that matches no row), so both paths cost the same query.
        // The failure write below runs only for a real account. Its few milliseconds are small next to the Argon2id
        // time and its variance. This rest is accepted.
        var throttledUntil = await _throttle
            .GetThrottledUntilAsync(context.Tenant.Id, user?.Id ?? Guid.Empty, source, cancellationToken)
            .ConfigureAwait(false);
        var throttled = user is not null && throttledUntil > now;

        // One verification on every path. A null hash verifies against a dummy and fails: an unknown user, and a
        // throttled one, whose real password is not checked during the wait.
        var check = await _hasher.VerifyAsync(throttled ? null : user?.PasswordHash, password, cancellationToken).ConfigureAwait(false);

        string? reason = null;
        if (user is null)
        {
            reason = "unknown user";
        }
        else if (throttled)
        {
            reason = "throttled";
        }
        else if (!check.Verified)
        {
            reason = "wrong password";
            await RecordFailureAsync(context, user.Id, source, now, cancellationToken).ConfigureAwait(false);
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

        await _throttle.ResetAsync(context.Tenant.Id, user!.Id, source, cancellationToken).ConfigureAwait(false);
        await WriteAuditAsync(context, AuditEventTypes.LoginSucceeded, user.Id, null, cancellationToken).ConfigureAwait(false);
        return new LoginResult(user);
    }

    private async Task RecordFailureAsync(RequestContext context, Guid userId, string source, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var failures = await _throttle
            .RecordFailureAsync(context.Tenant.Id, userId, source, now, now - _throttleOptions.ResetAfter, cancellationToken)
            .ConfigureAwait(false);
        if (LoginThrottle.DelayAfter(failures, _throttleOptions.FreeFailures, _throttleOptions.MaxDelay) is { } delay)
        {
            await _throttle.ThrottleUntilAsync(context.Tenant.Id, userId, source, now + delay, cancellationToken).ConfigureAwait(false);
        }
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
