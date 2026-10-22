using System.Threading.Channels;
using Heimdall.Application.Audit;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Heimdall.Infrastructure.Stores;

/// <summary>
/// Writes audit events with group commit. A caller waits until a committed transaction holds its event, so a response
/// never leaves before its audit row is durable. One writer for each server drains the queue: all events that wait
/// share one transaction.
/// </summary>
/// <remarks>
/// <para>
/// With no load, each batch is one event and nothing waits for a timer. Under load, events collect while the previous
/// commit runs, so the batches grow by themselves. Requests open no connection of their own for audit.
/// </para>
/// <para>
/// <c>audit_events</c> has no row-level security: platform events have no tenant. The role grant keeps it append-only.
/// So one transaction can hold the events of every tenant. When a batch fails, the writer writes each event alone,
/// so one bad event fails only its own request.
/// </para>
/// </remarks>
internal sealed partial class BatchingAuditLog : IAuditLog, IAsyncDisposable
{
    /// <summary>The most events in one transaction. It bounds the size of one insert and one commit.</summary>
    internal const int MaxBatchSize = 256;

    private readonly IServiceScopeFactory _scopes;
    private readonly HeimdallMetrics _metrics;
    private readonly ILogger<BatchingAuditLog> _logger;
    private readonly Channel<Pending> _queue = Channel.CreateUnbounded<Pending>(new UnboundedChannelOptions { SingleReader = true });
    private readonly Task _writer;

    public BatchingAuditLog(IServiceScopeFactory scopes, HeimdallMetrics metrics, ILogger<BatchingAuditLog> logger)
    {
        _scopes = scopes;
        _metrics = metrics;
        _logger = logger;
        _writer = Task.Run(RunAsync);
    }

    /// <summary>The number of committed transactions. For tests.</summary>
    internal int Commits { get; private set; }

    public Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        var pending = new Pending(auditEvent);
        ObjectDisposedException.ThrowIf(!_queue.Writer.TryWrite(pending), this);

        // A caller that stops waiting does not remove its event. The event is still written.
        return pending.Committed.Task.WaitAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        _queue.Writer.TryComplete();
        await _writer.ConfigureAwait(false);
    }

    private async Task RunAsync()
    {
        var batch = new List<Pending>(MaxBatchSize);
        while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            while (batch.Count < MaxBatchSize && _queue.Reader.TryRead(out var pending))
            {
                batch.Add(pending);
            }

            await WriteBatchAsync(batch).ConfigureAwait(false);
            batch.Clear();
        }
    }

    // The writer must survive any failure, or every later caller would wait forever. Each failure goes to the callers
    // of the events that it affects.
#pragma warning disable CA1031
    private async Task WriteBatchAsync(List<Pending> batch)
    {
        try
        {
            await InsertAsync(batch).ConfigureAwait(false);
            batch.ForEach(p => p.Committed.TrySetResult());
            return;
        }
        catch (Exception exception) when (batch.Count > 1)
        {
            LogBatchFailed(_logger, exception, batch.Count);
        }
        catch (Exception exception)
        {
            batch[0].Committed.TrySetException(exception);
            return;
        }

        foreach (var pending in batch)
        {
            try
            {
                await InsertAsync([pending]).ConfigureAwait(false);
                pending.Committed.TrySetResult();
            }
            catch (Exception exception)
            {
                pending.Committed.TrySetException(exception);
            }
        }
    }
#pragma warning restore CA1031

    private async Task InsertAsync(IReadOnlyList<Pending> batch)
    {
        var scope = _scopes.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
        {
            // One SaveChanges is one transaction. EF Core sends the inserts in batched commands.
            var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
            db.AuditEvents.AddRange(batch.Select(p => p.Event));
            await db.SaveChangesAsync().ConfigureAwait(false);
        }

        Commits++;
        _metrics.AuditBatch(batch.Count);
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "An audit batch of {Count} events failed. Each event is written alone.")]
    private static partial void LogBatchFailed(ILogger logger, Exception exception, int count);

    private sealed class Pending(AuditEvent auditEvent)
    {
        public AuditEvent Event { get; } = auditEvent;

        // Continuations run on the thread pool, not on the writer, so a slow caller cannot delay the next batch.
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
