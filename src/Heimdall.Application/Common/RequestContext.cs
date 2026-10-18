using System.Net;
using Heimdall.Domain.Tenants;

namespace Heimdall.Application.Common;

/// <summary>
/// Facts about the current request that the Api layer resolves before a use case runs.
/// </summary>
/// <param name="Tenant">The tenant found from the host name (D21).</param>
/// <param name="Issuer">The issuer URL of this tenant, exactly as it appears in discovery and in the <c>iss</c> claim.</param>
/// <param name="CorrelationId">The ID that links logs and audit events for this request.</param>
/// <param name="SourceIp">The client IP address, if known.</param>
/// <param name="UserAgent">The browser's User-Agent header, shortened, for the audit log. Null for API clients.</param>
public sealed record RequestContext(Tenant Tenant, string Issuer, string CorrelationId, IPAddress? SourceIp, string? UserAgent = null);
