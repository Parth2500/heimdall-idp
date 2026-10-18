using Heimdall.Infrastructure.Purge;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Jobs;

/// <summary>
/// Runs <see cref="DataPurger"/> on each <see cref="PurgeOptions.Interval"/>. Every server runs it. <c>SKIP LOCKED</c>
/// makes concurrent runs safe: each row is deleted once, and no server waits for another.
/// </summary>
internal sealed partial class PurgeJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly PurgeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<PurgeJob> _logger;
    private readonly bool _loopEnabled;

    public PurgeJob(IServiceScopeFactory scopes, PurgeOptions options, TimeProvider time, ILogger<PurgeJob> logger, IOptions<BackgroundJobOptions> jobs)
    {
        _loopEnabled = jobs.Value.Enabled;
        _scopes = scopes;
        _options = options;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_loopEnabled)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            // Wait first: a server that starts has more urgent work than old rows.
            try
            {
                await Task.Delay(_options.Interval, _time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                var scope = _scopes.CreateAsyncScope();
                await using (scope.ConfigureAwait(false))
                {
                    var result = await scope.ServiceProvider.GetRequiredService<DataPurger>().RunOnceAsync(stoppingToken).ConfigureAwait(false);
                    LogPurged(_logger, result.Families, result.Codes, result.Requests, result.Sessions);
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // A failed pass must not stop the job. The next pass tries again.
                LogFailed(_logger, exception);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Purge pass deleted {Families} families, {Codes} codes, {Requests} requests, {Sessions} sessions.")]
    private static partial void LogPurged(ILogger logger, int families, int codes, int requests, int sessions);

    [LoggerMessage(Level = LogLevel.Error, Message = "The purge job pass failed.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
