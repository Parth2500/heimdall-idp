using System.Globalization;
using Heimdall.Application.Audit;
using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Heimdall.Infrastructure.Logout;

/// <summary>The calls of one delivery pass, by outcome.</summary>
public sealed record BackchannelPassResult(int Sent, int Failed, int Dropped);

/// <summary>
/// Sends the queued back-channel logouts (Back-Channel Logout 1.0, D34, D35). It is a platform operation across all
/// tenants, so it uses SQL statements and the platform role (<see cref="PlatformDbContextFactory"/>).
/// </summary>
/// <remarks>
/// A pass takes the due rows with one statement: it counts the attempt and moves <c>next_attempt_at</c> by the lease.
/// <c>SKIP LOCKED</c> lets every server run the job: each row goes to one server. A server that stops during a call
/// leaves the row, and the lease brings it back. So a client can get a logout token twice. Each one has a new
/// <c>jti</c>, and both name the same session, so a second one changes nothing at the client.
/// </remarks>
public sealed partial class BackchannelLogoutDelivery : IDisposable
{
    private readonly PlatformDbContextFactory _platform;
    private readonly ITokenSigner _signer;
    private readonly IIssuerResolver _issuers;
    private readonly IAuditLog _audit;
    private readonly HeimdallMetrics _metrics;
    private readonly BackchannelLogoutOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<BackchannelLogoutDelivery> _logger;
    private readonly HttpClient _http;

    public BackchannelLogoutDelivery(
        PlatformDbContextFactory platform,
        ITokenSigner signer,
        IIssuerResolver issuers,
        IAuditLog audit,
        HeimdallMetrics metrics,
        BackchannelLogoutOptions options,
        TimeProvider time,
        ILogger<BackchannelLogoutDelivery> logger)
        : this(platform, signer, issuers, audit, metrics, options, time, logger, CreateHandler(options))
    {
    }

    /// <summary>For tests: the handler replaces the network.</summary>
    internal BackchannelLogoutDelivery(
        PlatformDbContextFactory platform,
        ITokenSigner signer,
        IIssuerResolver issuers,
        IAuditLog audit,
        HeimdallMetrics metrics,
        BackchannelLogoutOptions options,
        TimeProvider time,
        ILogger<BackchannelLogoutDelivery> logger,
        HttpMessageHandler handler)
    {
        _platform = platform;
        _signer = signer;
        _issuers = issuers;
        _audit = audit;
        _metrics = metrics;
        _options = options;
        _time = time;
        _logger = logger;

        // The time limit is per call, set on each request. The client itself has none, so no other limit cuts in.
        _http = new HttpClient(handler) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("Heimdall-BackchannelLogout/1.0");
    }

    public void Dispose() => _http.Dispose();

    /// <summary>
    /// D35: one POST, no redirect, no response body. The address check runs on the resolved address at connect time,
    /// outside Development.
    /// </summary>
    internal static SocketsHttpHandler CreateHandler(BackchannelLogoutOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = options.Timeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };
        if (options.BlockPrivateAddresses)
        {
            handler.ConnectCallback = OutboundAddressGuard.ConnectAsync;
        }

        return handler;
    }

    public async Task<BackchannelPassResult> RunOnceAsync(CancellationToken cancellationToken)
    {
        var db = _platform.Create();
        await using var dispose = db.ConfigureAwait(false);
        var now = _time.GetUtcNow();
        var leaseUntil = now + _options.Lease;
        var batch = _options.BatchSize;

        // docs/schema-design.md, "Deliver a back-channel logout". The attempt counts before the call, so a server that
        // stops during the call still uses up an attempt, and a row cannot come back forever.
        var rows = await db.BackchannelLogouts
            .FromSql($"""
                UPDATE backchannel_logouts
                SET    attempts = attempts + 1, next_attempt_at = {leaseUntil}
                WHERE  id IN (
                    SELECT id FROM backchannel_logouts
                    WHERE  next_attempt_at <= {now}
                    ORDER  BY next_attempt_at
                    LIMIT  {batch}
                    FOR UPDATE SKIP LOCKED)
                RETURNING *
                """)
            .IgnoreQueryFilters() // A platform pass has no tenant. The statement names no tenant on purpose.
            .AsNoTracking()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (rows.Count == 0)
        {
            return new BackchannelPassResult(0, 0, 0);
        }

        var clientPks = rows.Select(r => r.ClientPk).Distinct().ToList();
        var targets = await (
                from c in db.Clients.IgnoreQueryFilters()
                join t in db.Tenants on c.TenantId equals t.Id
                where clientPks.Contains(c.Id)
                select new Target(c.TenantId, c.Id, c.ClientId, c.BackchannelLogoutUri, t.Host))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        // The calls of one pass run at the same time (Back-Channel Logout 1.0, section 2.3), so one slow client does not
        // hold up the others. Each call has its own time limit.
        var outcomes = await Task.WhenAll(rows.Select(row =>
            DeliverAsync(row, targets.SingleOrDefault(t => t.TenantId == row.TenantId && t.ClientPk == row.ClientPk), now, cancellationToken)))
            .ConfigureAwait(false);

        int sent = 0, failed = 0, dropped = 0;
        for (var i = 0; i < rows.Count; i++)
        {
            var row = rows[i];
            if (outcomes[i] == Outcome.Sent || outcomes[i] == Outcome.NoTarget)
            {
                await DeleteAsync(db, row, cancellationToken).ConfigureAwait(false);
                sent += outcomes[i] == Outcome.Sent ? 1 : 0;
                continue;
            }

            if (row.Attempts > _options.MaxRetries)
            {
                await DeleteAsync(db, row, cancellationToken).ConfigureAwait(false);
                await WriteDroppedAsync(row, targets, cancellationToken).ConfigureAwait(false);
                _metrics.BackchannelLogout("dropped");
                dropped++;
                continue;
            }

            // The waits double: 30 s, 1 min, 2 min, 4 min, 8 min with the default settings.
            var retryAt = now + (_options.FirstRetryDelay * Math.Pow(2, row.Attempts - 1));
            await db.Database.ExecuteSqlAsync(
                $"UPDATE backchannel_logouts SET next_attempt_at = {retryAt} WHERE id = {row.Id}",
                cancellationToken).ConfigureAwait(false);
            _metrics.BackchannelLogout("failed");
            failed++;
        }

        return new BackchannelPassResult(sent, failed, dropped);
    }

    private async Task<Outcome> DeliverAsync(BackchannelLogoutRecord row, Target? target, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (target?.Uri is not { } uri)
        {
            // The client is gone, or it removed its URI after the sign-out. Nobody waits for this call.
            LogNoTarget(_logger, row.ClientPk);
            return Outcome.NoTarget;
        }

        try
        {
            var token = await _signer.SignLogoutTokenAsync(
                row.TenantId,
                new LogoutTokenClaims(
                    _issuers.IssuerFor(target.Host),
                    row.UserId.ToString(),
                    target.ClientId,
                    now,
                    now + BackchannelLogoutOptions.TokenLifetime,
                    Guid.NewGuid().ToString("N"),
                    row.Sid),
                cancellationToken).ConfigureAwait(false);

            using var request = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new FormUrlEncodedContent([new("logout_token", token)]),
            };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.Timeout);

            // Headers only: Heimdall reads no response body, so a client cannot make it read a large one.
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                _metrics.BackchannelLogout("sent");
                return Outcome.Sent;
            }

            LogFailed(_logger, target.ClientId, row.Attempts, $"HTTP {(int)response.StatusCode}", null);
            return Outcome.Failed;
        }
        catch (Exception exception) when (
            exception is HttpRequestException or SigningKeyUnavailableException
            || (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            LogFailed(_logger, target.ClientId, row.Attempts, exception.GetType().Name, exception);
            return Outcome.Failed;
        }
    }

    private static Task<int> DeleteAsync(HeimdallDbContext db, BackchannelLogoutRecord row, CancellationToken cancellationToken) =>
        db.Database.ExecuteSqlAsync($"DELETE FROM backchannel_logouts WHERE id = {row.Id}", cancellationToken);

    /// <summary>D35: the last retry failed. The audit log keeps the evidence that the client did not get the logout.</summary>
    private Task WriteDroppedAsync(BackchannelLogoutRecord row, List<Target> targets, CancellationToken cancellationToken)
    {
        var clientId = targets.SingleOrDefault(t => t.TenantId == row.TenantId && t.ClientPk == row.ClientPk)?.ClientId ?? string.Empty;
        LogDropped(_logger, clientId, row.Attempts);
        return _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                row.TenantId,
                AuditEventTypes.BackchannelLogoutDropped,
                "backchannel-" + row.Id.ToString("N"),
                _time.GetUtcNow(),
                null,
                subjectUserId: row.UserId,
                clientPk: row.ClientPk,
                data: new Dictionary<string, string>
                {
                    ["client_id"] = clientId,
                    ["sid"] = row.Sid,
                    ["attempts"] = row.Attempts.ToString(CultureInfo.InvariantCulture),
                }),
            cancellationToken);
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Back-channel logout to client {ClientId} failed on attempt {Attempt}: {Reason}.")]
    private static partial void LogFailed(ILogger logger, string clientId, int attempt, string reason, Exception? exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Back-channel logout to client {ClientId} dropped after {Attempts} attempts.")]
    private static partial void LogDropped(ILogger logger, string clientId, int attempts);

    [LoggerMessage(Level = LogLevel.Information, Message = "Back-channel logout for client {ClientPk} skipped: the client or its URI is gone.")]
    private static partial void LogNoTarget(ILogger logger, Guid clientPk);

    private enum Outcome
    {
        Sent,
        Failed,
        NoTarget,
    }

    private sealed record Target(Guid TenantId, Guid ClientPk, string ClientId, string? Uri, string Host);
}
