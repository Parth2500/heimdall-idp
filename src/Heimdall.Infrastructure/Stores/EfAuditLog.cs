using Heimdall.Application.Audit;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfAuditLog : IAuditLog
{
    private readonly HeimdallDbContext _db;

    public EfAuditLog(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        _db.AuditEvents.Add(auditEvent);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
