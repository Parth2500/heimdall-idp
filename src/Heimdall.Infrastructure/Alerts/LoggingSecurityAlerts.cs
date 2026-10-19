using System.Text.Json;
using Heimdall.Application.Alerts;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.Extensions.Logging;

namespace Heimdall.Infrastructure.Alerts;

/// <summary>
/// Writes each alert as one structured log line at Critical level, with the event name "SecurityAlert". A log
/// pipeline can page on it. A pager or SIEM integration can replace this class later.
/// </summary>
internal sealed partial class LoggingSecurityAlerts : ISecurityAlerts
{
    private readonly ILogger<LoggingSecurityAlerts> _logger;
    private readonly HeimdallMetrics _metrics;

    public LoggingSecurityAlerts(ILogger<LoggingSecurityAlerts> logger, HeimdallMetrics metrics)
    {
        _logger = logger;
        _metrics = metrics;
    }

    public void Raise(string type, Guid tenantId, IReadOnlyDictionary<string, string> data)
    {
        // An alert is rare and must never be dropped, so the data is always serialized.
        var json = JsonSerializer.Serialize(data);
        LogAlert(_logger, type, tenantId, json);
        _metrics.SecurityAlert(type);
    }

    [LoggerMessage(EventId = 9000, EventName = "SecurityAlert", Level = LogLevel.Critical, Message = "Security alert {AlertType} in tenant {TenantId}: {Data}")]
    private static partial void LogAlert(ILogger logger, string alertType, Guid tenantId, string data);
}
