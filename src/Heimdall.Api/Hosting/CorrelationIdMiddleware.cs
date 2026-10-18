using System.Text.RegularExpressions;

namespace Heimdall.Api.Hosting;

/// <summary>
/// Gives each request a correlation ID. Logs and audit events of the request carry it (D7). The ID goes back in
/// the response, so a client can quote it in a support request.
/// </summary>
/// <remarks>
/// A caller may send its own ID. Heimdall accepts it only when it is short and plain, because the value goes into
/// logs and audit events. Any other value is replaced, so a caller cannot inject text into a log line.
/// </remarks>
internal sealed partial class CorrelationIdMiddleware
{
    public const string HeaderName = "X-Correlation-ID";

    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var incoming = context.Request.Headers[HeaderName];
        var id = incoming.Count == 1 && SafeId().IsMatch(incoming[0]!)
            ? incoming[0]!
            : Guid.NewGuid().ToString("N");

        context.TraceIdentifier = id;
        context.Response.Headers[HeaderName] = id;

        using (_logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = id }))
        {
            await _next(context).ConfigureAwait(false);
        }
    }

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeId();
}
