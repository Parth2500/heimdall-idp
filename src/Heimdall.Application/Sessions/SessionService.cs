using System.Buffers.Text;
using System.Security.Cryptography;
using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;

namespace Heimdall.Application.Sessions;

/// <param name="SessionId">The new session ID for the cookie. Shown only here; the server keeps only its hash.</param>
/// <param name="User">The signed-in user.</param>
public sealed record SignInResult(string? SessionId, User? User)
{
    public static SignInResult Failed { get; } = new(null, null);

    public bool Succeeded => SessionId is not null;
}

/// <param name="Session">The valid session.</param>
/// <param name="User">Its user.</param>
public sealed record ValidSession(Session Session, User User);

/// <summary>
/// Login sessions at Heimdall (D11 to D13, D18). The cookie holds a random 256-bit ID. The server stores only its
/// SHA-256 hash, so a database leak gives no usable session (D12).
/// </summary>
public sealed class SessionService
{
    /// <summary>The length of a session ID: 32 random bytes as base64url without padding.</summary>
    public const int SessionIdLength = 43;

    // Activity moves the idle limit. Writing it at most once a minute keeps validation from writing on every request.
    private static readonly TimeSpan TouchInterval = TimeSpan.FromMinutes(1);

    private readonly UserAuthenticator _authenticator;
    private readonly ISessionStore _sessions;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public SessionService(
        UserAuthenticator authenticator,
        ISessionStore sessions,
        IAuditLog audit,
        TimeProvider time)
    {
        _authenticator = authenticator;
        _sessions = sessions;
        _audit = audit;
        _time = time;
    }

    /// <summary>
    /// Signs in with email and password. On success, the browser's old session (if any) ends and a new session ID is
    /// issued, so an ID that an attacker planted before sign-in is worthless (D13, session fixation).
    /// </summary>
    /// <exception cref="PasswordHasherBusyException">The server is at its hashing limit.</exception>
    public async Task<SignInResult> SignInAsync(
        RequestContext context,
        string? email,
        string? password,
        string? existingSessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var login = await _authenticator.AuthenticateAsync(context, email, password, cancellationToken).ConfigureAwait(false);
        if (!login.Succeeded)
        {
            return SignInResult.Failed;
        }

        var now = _time.GetUtcNow();
        if (TryHash(existingSessionId) is { } oldHash
            && await _sessions.FindAsync(context.Tenant.Id, oldHash, cancellationToken).ConfigureAwait(false) is { } old)
        {
            old.Revoke(now);
        }

        var sessionId = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        // D29: the public sid is separate random bits. It must not be derived from the cookie secret.
        var sid = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        var session = Session.Start(TokenHash.Compute(sessionId), sid, context.Tenant.Id, login.User!.Id, context.Tenant.Settings.SessionAbsolute, now);
        _sessions.Add(session);
        await _sessions.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await WriteAuditAsync(context, AuditEventTypes.SessionStarted, session, cancellationToken).ConfigureAwait(false);
        return new SignInResult(sessionId, login.User);
    }

    /// <summary>
    /// Returns the session and its user when every rule holds (see <see cref="Session.IsValid"/>): the tenant matches,
    /// the user is active, the password did not change since sign-in, and neither the idle nor the absolute limit passed.
    /// </summary>
    public async Task<ValidSession?> ValidateAsync(RequestContext context, string? sessionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // A malformed cookie is refused before the database.
        if (TryHash(sessionId) is not { } hash)
        {
            return null;
        }

        if (await _sessions.FindWithUserAsync(context.Tenant.Id, hash, cancellationToken).ConfigureAwait(false) is not var (session, user))
        {
            return null;
        }

        var now = _time.GetUtcNow();
        if (!session.IsValid(context.Tenant.Id, user, context.Tenant.Settings.SessionIdle, now))
        {
            return null;
        }

        if (now - session.LastSeenAt >= TouchInterval)
        {
            session.Touch(now);
            await _sessions.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return new ValidSession(session, user);
    }

    /// <summary>Ends the session. Signing out twice, or with no session, does nothing.</summary>
    public async Task SignOutAsync(RequestContext context, string? sessionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (TryHash(sessionId) is not { } hash)
        {
            return;
        }

        var session = await _sessions.FindAsync(context.Tenant.Id, hash, cancellationToken).ConfigureAwait(false);
        if (session is not { RevokedAt: null })
        {
            return;
        }

        session.Revoke(_time.GetUtcNow());
        await _sessions.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await WriteAuditAsync(context, AuditEventTypes.SessionRevoked, session, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The hash of a well-formed session ID, or null. Only base64url text of the exact length is accepted.</summary>
    private static TokenHash? TryHash(string? sessionId) =>
        sessionId is { Length: SessionIdLength } && Base64Url.IsValid(sessionId) ? TokenHash.Compute(sessionId) : null;

    private Task WriteAuditAsync(RequestContext context, string type, Session session, CancellationToken cancellationToken)
    {
        var data = new Dictionary<string, string>
        {
            // The hash, never the ID. It links events of one session without giving anyone a usable cookie.
            ["session_hash"] = Convert.ToHexStringLower(session.IdHash.AsSpan()),
        };
        if (context.UserAgent is { } userAgent)
        {
            data["user_agent"] = userAgent;
        }

        return _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                type,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: session.UserId,
                data: data),
            cancellationToken);
    }
}
