using System.Diagnostics.Metrics;

namespace Heimdall.Infrastructure.Telemetry;

/// <summary>
/// Heimdall's own metrics, in the meter <see cref="MeterName"/>. OpenTelemetry exports them with the ASP.NET Core,
/// runtime, and Npgsql metrics.
/// </summary>
/// <remarks>
/// Every tag value comes from a fixed set, never from request input, so a caller cannot create unbounded tag values
/// (memory and cost of the metrics backend). No tag carries a client ID, a user, or a token (D7).
/// </remarks>
public sealed class HeimdallMetrics
{
    public const string MeterName = "Heimdall";

    private static readonly string[] KnownGrantTypes = ["authorization_code", "refresh_token", "client_credentials"];

    private readonly Counter<long> _tokenRequests;
    private readonly Counter<long> _loginAttempts;
    private readonly Histogram<double> _hashQueueWait;
    private readonly Counter<long> _hashRejected;
    private readonly Counter<long> _securityAlerts;
    private readonly Counter<long> _cacheLookups;
    private readonly Histogram<int> _auditBatchSize;

    public HeimdallMetrics(IMeterFactory meterFactory)
    {
        ArgumentNullException.ThrowIfNull(meterFactory);
        var meter = meterFactory.Create(MeterName);
        _tokenRequests = meter.CreateCounter<long>("heimdall.token.requests", "{request}", "Token requests, by grant type and outcome.");
        _loginAttempts = meter.CreateCounter<long>("heimdall.login.attempts", "{attempt}", "Sign-in attempts, by outcome. A rise in failures can mean credential stuffing.");
        _hashQueueWait = meter.CreateHistogram<double>("heimdall.password_hash.queue_wait", "s", "Time a request waits for a password hash slot.");
        _hashRejected = meter.CreateCounter<long>("heimdall.password_hash.rejected", "{request}", "Requests refused because every hash slot stayed busy.");
        _securityAlerts = meter.CreateCounter<long>("heimdall.security.alerts", "{alert}", "Security alerts, by type, such as code or refresh token reuse.");
        _cacheLookups = meter.CreateCounter<long>("heimdall.cache.lookups", "{lookup}", "In-memory cache lookups, by cache and result.");
        _auditBatchSize = meter.CreateHistogram<int>("heimdall.audit.batch_size", "{event}", "Audit events in one committed transaction. Larger batches mean more load.");
    }

    /// <param name="grantType">The raw grant_type. An unknown value is counted as "other".</param>
    /// <param name="outcome">"success" or an OAuth error code.</param>
    public void TokenRequest(string? grantType, string outcome) =>
        _tokenRequests.Add(
            1,
            new KeyValuePair<string, object?>("grant_type", grantType is not null && KnownGrantTypes.Contains(grantType) ? grantType : "other"),
            new KeyValuePair<string, object?>("outcome", outcome));

    /// <param name="outcome">"success", "failure", or "busy".</param>
    public void LoginAttempt(string outcome) => _loginAttempts.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    public void PasswordHashQueueWait(TimeSpan wait) => _hashQueueWait.Record(wait.TotalSeconds);

    public void PasswordHashRejected() => _hashRejected.Add(1);

    /// <param name="type">An audit event type constant, such as <c>refresh.reuse_detected</c>.</param>
    public void SecurityAlert(string type) => _securityAlerts.Add(1, new KeyValuePair<string, object?>("type", type));

    public void AuditBatch(int size) => _auditBatchSize.Record(size);

    /// <param name="cache">A fixed cache name: "tenants", "clients", or "signing_keys".</param>
    public void CacheLookup(string cache, bool hit) =>
        _cacheLookups.Add(1, new KeyValuePair<string, object?>("cache", cache), new KeyValuePair<string, object?>("result", hit ? "hit" : "miss"));
}
