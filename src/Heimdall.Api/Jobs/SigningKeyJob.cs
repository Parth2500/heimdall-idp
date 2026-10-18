using Heimdall.Application.Keys;
using Heimdall.Infrastructure.Persistence;

namespace Heimdall.Api.Jobs;

/// <summary>
/// Keeps each tenant's signing keys in their target state: it creates a first key, activates it when its publish
/// wait ends, creates the next key before rotation is due, and rotates. Every server runs this job. The database
/// rules make concurrent runs safe: one server wins each change, and the others change nothing.
/// </summary>
internal sealed partial class SigningKeyJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly SigningKeyOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<SigningKeyJob> _logger;

    public SigningKeyJob(IServiceScopeFactory scopes, SigningKeyOptions options, TimeProvider time, ILogger<SigningKeyJob> logger)
    {
        _scopes = scopes;
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>One pass over the tenants that need key work. Returns the number of changes this server made.</summary>
    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();

        // An active key that signs since this time is within one publish wait of rotation, or past it.
        var activeSigningSince = now - (_options.RotationInterval - _options.PublishWait);

        IReadOnlyList<Guid> tenantIds;
        var listScope = _scopes.CreateAsyncScope();
        await using (listScope.ConfigureAwait(false))
        {
            tenantIds = await listScope.ServiceProvider.GetRequiredService<ISigningKeyStore>()
                .ListTenantsNeedingKeyWorkAsync(now, activeSigningSince, cancellationToken)
                .ConfigureAwait(false);
        }

        var changes = 0;
        foreach (var tenantId in tenantIds)
        {
            // One scope for each tenant: the tenant of a database context cannot change (D20).
            var scope = _scopes.CreateAsyncScope();
            await using (scope.ConfigureAwait(false))
            {
                scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenantId);
                var action = await scope.ServiceProvider.GetRequiredService<SigningKeyService>()
                    .MaintainAsync(tenantId, "job-" + Guid.NewGuid().ToString("N"), cancellationToken)
                    .ConfigureAwait(false);

                if (action != KeyMaintenanceAction.None)
                {
                    changes++;
                    LogChange(_logger, tenantId, action);
                }
            }
        }

        return changes;
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

    [LoggerMessage(Level = LogLevel.Information, Message = "Signing keys of tenant {TenantId}: {Action}.")]
    private static partial void LogChange(ILogger logger, Guid tenantId, KeyMaintenanceAction action);

    [LoggerMessage(Level = LogLevel.Error, Message = "The signing key job pass failed.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}
