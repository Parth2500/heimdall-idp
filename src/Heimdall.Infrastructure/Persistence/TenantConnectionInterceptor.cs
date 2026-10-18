using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Heimdall.Infrastructure.Persistence;

/// <summary>
/// Sets <c>app.tenant_id</c> on each connection open, from the <see cref="TenantScope"/> of the database context. The
/// row-level security policies compare <c>tenant_id</c> with it (D20, second layer).
/// </summary>
/// <remarks>
/// EF Core opens a pooled connection for each command, or once for a transaction. The value is set on every open, and
/// set to empty when the scope has no tenant. So a value never carries over from one request to the next through the
/// connection pool. An empty value matches no row (fail closed).
/// </remarks>
internal sealed class TenantConnectionInterceptor : DbConnectionInterceptor
{
    private readonly TenantScope _scope;

    public TenantConnectionInterceptor(TenantScope scope)
    {
        _scope = scope;
    }

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        using var command = CreateCommand(connection);
        command.ExecuteNonQuery();
    }

    public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
    {
        var command = CreateCommand(connection);
        await using (command.ConfigureAwait(false))
        {
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private DbCommand CreateCommand(DbConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var command = connection.CreateCommand();

        // A parameter, never string concatenation. is_local = false: the value lasts until the next open sets it again.
        command.CommandText = "SELECT set_config('app.tenant_id', @tenant, false)";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "tenant";
        parameter.Value = _scope.TenantId?.ToString() ?? string.Empty;
        command.Parameters.Add(parameter);
        return command;
    }
}
