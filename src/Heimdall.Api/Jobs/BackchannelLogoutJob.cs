using Heimdall.Infrastructure.Logout;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Jobs;

/// <summary>
/// Runs <see cref="BackchannelLogoutDelivery"/> on each <see cref="BackchannelLogoutOptions.Interval"/> (D35). Every
/// server runs it. <c>SKIP LOCKED</c> gives each row to one server, and the user's sign-out never waits for a call.
/// </summary>
internal sealed partial class BackchannelLogoutJob : BackgroundService
{
    private readonly BackchannelLogoutDelivery _delivery;
    private readonly BackchannelLogoutOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<BackchannelLogoutJob> _logger;
    private readonly bool _loopEnabled;

    public BackchannelLogoutJob(
        BackchannelLogoutDelivery delivery,
        BackchannelLogoutOptions options,
        TimeProvider time,
        ILogger<BackchannelLogoutJob> logger,
        IOptions<BackgroundJobOptions> jobs)
    {
        _loopEnabled = jobs.Value.Enabled;
        _delivery = delivery;
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
                var result = await _delivery.RunOnceAsync(stoppingToken).ConfigureAwait(false);
                if (result.Sent + result.Failed + result.Dropped > 0)
                {
                    LogPass(_logger, result.Sent, result.Failed, result.Dropped);
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // A failed pass must not stop the job. The leases bring the rows back for the next pass.
                LogFailed(_logger, exception);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Back-channel logout pass: {Sent} sent, {Failed} failed, {Dropped} dropped.")]
    private static partial void LogPass(ILogger logger, int sent, int failed, int dropped);

    [LoggerMessage(Level = LogLevel.Error, Message = "The back-channel logout pass failed.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
