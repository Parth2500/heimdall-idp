namespace Heimdall.Application.Alerts;

/// <summary>
/// Signals that need a person, not only an audit row: for example a reused code or refresh token, which means a token
/// was stolen. The implementation writes a structured log line at Critical level today. A pager or SIEM can read it.
/// </summary>
public interface ISecurityAlerts
{
    void Raise(string type, Guid tenantId, IReadOnlyDictionary<string, string> data);
}
