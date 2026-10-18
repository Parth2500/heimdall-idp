using Heimdall.Application.Keys;
using Heimdall.Infrastructure.Persistence;

namespace Heimdall.Api.Jobs;

/// <summary>
/// Activates the first key of each tenant when its publish wait ends. Every server runs this job. The database
/// allows one active key for each tenant, so when two servers activate at the same time, one wins and the other
/// does nothing.
/// </summary>
internal sealed partial class SigningKeyActivationJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly SigningKeyOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<SigningKeyActivationJob> _logger;

    public SigningKeyActivationJob(
        IServiceScopeFactory scopes,
        SigningKeyOptions options,
        TimeProvider time,
        ILogger<SigningKeyActivationJob> logger)
    {
        _scopes = scopes;
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>One pass over all tenants. Returns the number of keys this server activated.</summary>
    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<Guid> tenantIds;
        var listScope = _scopes.CreateAsyncScope();
        await using (listScope.ConfigureAwait(false))
        {
            tenantIds = await listScope.ServiceProvider.GetRequiredService<ISigningKeyStore>()
                .ListTenantsAwaitingActivationAsync(_time.GetUtcNow(), cancellationToken)
                .ConfigureAwait(false);
        }

        var activated = 0;
        foreach (var tenantId in tenantIds)
        {
            // One scope for each tenant: the tenant of a database context cannot change (D20).
            var scope = _scopes.CreateAsyncScope();
            await using (scope.ConfigureAwait(false))
            {
                scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
                var key = await scope.ServiceProvider.GetRequiredService<SigningKeyService>()
                    .ActivateFirstKeyAsync(tenantId, "job-" + Guid.NewGuid().ToString("N"), cancellationToken)
                    .ConfigureAwait(false);

                if (key is not null)
                {
                    activated++;
                    LogActivated(_logger, tenantId, key.Kid);
                }
            }
        }

        return activated;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // A failed pass must not stop the job. The next pass tries again.
                LogFailed(_logger, exception);
            }

            try
            {
                await Task.Delay(_options.ActivationCheckInterval, _time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Signing key {Kid} of tenant {TenantId} is now active.")]
    private static partial void LogActivated(ILogger logger, Guid tenantId, string kid);

    [LoggerMessage(Level = LogLevel.Error, Message = "The signing key activation pass failed.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
