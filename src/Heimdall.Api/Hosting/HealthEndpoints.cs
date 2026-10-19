using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Heimdall.Api.Hosting;

/// <summary>Where the health endpoints answer.</summary>
public sealed class HealthOptions
{
    public const string SectionName = "Heimdall:Health";

    /// <summary>
    /// The management port. When it is set, the health endpoints answer only on this port. Do not publish this port to
    /// the internet. Null answers on every port, for local development.
    /// </summary>
    public int? Port { get; set; }
}

/// <summary>
/// <c>/health/live</c> and <c>/health/ready</c> for the orchestrator. They run before tenant resolution and before the
/// HTTPS check: a probe calls the container IP over plain HTTP, with no tenant host. The body is one word
/// (<c>Healthy</c> or <c>Unhealthy</c>), never the reason, so a caller learns nothing about the database.
/// </summary>
internal static class HealthEndpoints
{
    public const string LivePath = "/health/live";
    public const string ReadyPath = "/health/ready";
    private const string ReadyTag = "ready";

    public static IServiceCollection AddHeimdallHealthChecks(this IServiceCollection services)
    {
        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database", tags: [ReadyTag]);
        return services;
    }

    public static void UseHeimdallHealthChecks(this WebApplication app, HealthOptions options)
    {
        // Live: the process answers. No dependency check, so a database outage does not make the orchestrator restart
        // every server at once.
        var live = new HealthCheckOptions { Predicate = _ => false, ResponseWriter = WriteAsync };
        var ready = new HealthCheckOptions { Predicate = check => check.Tags.Contains(ReadyTag), ResponseWriter = WriteAsync };

        if (options.Port is { } port)
        {
            app.UseHealthChecks(LivePath, port, live);
            app.UseHealthChecks(ReadyPath, port, ready);
        }
        else
        {
            app.UseHealthChecks(LivePath, live);
            app.UseHealthChecks(ReadyPath, ready);
        }
    }

    private static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.ContentType = "text/plain";
        return context.Response.WriteAsync(report.Status == HealthStatus.Healthy ? "Healthy" : "Unhealthy", context.RequestAborted);
    }

    /// <summary>Ready means the database answers. Without it, no endpoint except JWKS and discovery can work.</summary>
    private sealed class DatabaseHealthCheck : IHealthCheck
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);
        private readonly HeimdallDbContext _db;

        public DatabaseHealthCheck(HeimdallDbContext db)
        {
            _db = db;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(Timeout);
            try
            {
                return await _db.Database.CanConnectAsync(timeout.Token).ConfigureAwait(false)
                    ? HealthCheckResult.Healthy()
                    : HealthCheckResult.Unhealthy("database unreachable");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return HealthCheckResult.Unhealthy("database timeout");
            }
        }
    }
}
