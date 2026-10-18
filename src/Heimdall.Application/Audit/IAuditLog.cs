using Heimdall.Domain.Audit;

namespace Heimdall.Application.Audit;

/// <summary>
/// Writes audit events. If a write fails, the request fails too: an action without a record is not allowed.
/// </summary>
public interface IAuditLog
{
    Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken);
}
