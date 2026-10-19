using System.Globalization;
using System.Text.Json;
using System.Threading.RateLimiting;
using Heimdall.Api.Endpoints;
using Heimdall.Application.Common;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Hosting;

/// <summary>One sliding-window limit: <see cref="PermitLimit"/> permits in each <see cref="Window"/>.</summary>
public sealed class RateLimit
{
    public int PermitLimit { get; set; }

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>
/// Rate limits for each server (threat model, Limits and lifetimes). The counters are in memory, so with N servers a
/// caller gets up to N times each limit. That still caps the CPU and database load of each server, which is the
/// purpose. The per-account sign-in throttle is in the database, so it is exact across servers.
/// </summary>
public sealed class RateLimitOptions
{
    public const string SectionName = "Heimdall:RateLimits";

    /// <summary>Sign-in attempts for each IP. Each attempt costs one Argon2id hash, success or failure.</summary>
    public RateLimit Login { get; set; } = new() { PermitLimit = 5 };

    /// <summary><c>/authorize</c> requests for each IP. Each one can store an authorization request.</summary>
    public RateLimit Authorize { get; set; } = new() { PermitLimit = 120 };

    /// <summary>Failed <c>/token</c> and <c>/revoke</c> requests for each IP. A backend's normal traffic does not count.</summary>
    public RateLimit ClientFailures { get; set; } = new() { PermitLimit = 60 };

    /// <summary>Successful token issuances for each authenticated client. Only the client's own successes count.</summary>
    public RateLimit ClientIssuance { get; set; } = new() { PermitLimit = 300 };

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        foreach (var (name, limit) in new[] { (nameof(Login), Login), (nameof(Authorize), Authorize), (nameof(ClientFailures), ClientFailures), (nameof(ClientIssuance), ClientIssuance) })
        {
            if (limit.PermitLimit < 1)
            {
                errors.Add($"{name}: {nameof(RateLimit.PermitLimit)} must be at least 1.");
            }

            if (limit.Window < TimeSpan.FromSeconds(1))
            {
                errors.Add($"{name}: {nameof(RateLimit.Window)} must be at least one second.");
            }
        }

        return errors;
    }
}

/// <summary>
/// The limits that count only some requests, which the ASP.NET Core rate limiter middleware cannot do: failures for each
/// IP at /token and /revoke, and successful issuances for each client. A check reads the counter without a change; a
/// record takes a permit. Two concurrent requests can pass one check together, so a limit can be exceeded by a few.
/// </summary>
internal sealed class ClientRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> _failures;
    private readonly PartitionedRateLimiter<string> _issuance;
    private readonly RateLimitOptions _options;

    public ClientRateLimiter(IOptions<RateLimitOptions> options)
    {
        _options = options.Value;
        _failures = Create(_options.ClientFailures);
        _issuance = Create(_options.ClientIssuance);
    }

    /// <summary>True when this IP has used its failure budget. Check it first, before any database work.</summary>
    public bool IsIpBlocked(HttpContext context) => IsExhausted(_failures, RateLimits.IpKey(context));

    public void RecordFailure(HttpContext context) => _failures.AttemptAcquire(RateLimits.IpKey(context)).Dispose();

    /// <param name="clientId">The client ID from the request. Only a check: a wrong secret consumes nothing here.</param>
    public bool IsClientBlocked(Guid tenantId, string? clientId) =>
        clientId is not null && IsExhausted(_issuance, ClientKey(tenantId, clientId));

    /// <summary>Call after a successful issuance only, so no caller can use up another client's budget.</summary>
    public void RecordIssued(Guid tenantId, string clientId) => _issuance.AttemptAcquire(ClientKey(tenantId, clientId)).Dispose();

    public TimeSpan FailureWindow => _options.ClientFailures.Window;

    public TimeSpan IssuanceWindow => _options.ClientIssuance.Window;

    public void Dispose()
    {
        _failures.Dispose();
        _issuance.Dispose();
    }

    private static string ClientKey(Guid tenantId, string clientId) => tenantId.ToString("N") + ":" + clientId;

    private static bool IsExhausted(PartitionedRateLimiter<string> limiter, string key) =>
        limiter.GetStatistics(key) is { CurrentAvailablePermits: <= 0 };

    private static PartitionedRateLimiter<string> Create(RateLimit limit) =>
        PartitionedRateLimiter.Create<string, string>(key => RateLimitPartition.GetSlidingWindowLimiter(key, _ => RateLimits.SlidingWindow(limit)));
}

/// <summary>Registration and shared parts of the rate limits.</summary>
internal static class RateLimits
{
    public const string LoginPolicy = "login";
    public const string AuthorizePolicy = "authorize";

    public static IServiceCollection AddHeimdallRateLimits(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RateLimitOptions>()
            .Bind(configuration.GetSection(RateLimitOptions.SectionName))
            .Validate(options => options.Validate().Count == 0, "Invalid settings in " + RateLimitOptions.SectionName + ".")
            .ValidateOnStart();
        services.AddSingleton<ClientRateLimiter>();

        services.AddRateLimiter(_ => { });
        services.AddOptions<RateLimiterOptions>().Configure<IOptions<RateLimitOptions>>((limiter, limits) =>
        {
            limiter.AddPolicy(LoginPolicy, context => RateLimitPartition.GetSlidingWindowLimiter(IpKey(context), _ => SlidingWindow(limits.Value.Login)));
            limiter.AddPolicy(AuthorizePolicy, context => RateLimitPartition.GetSlidingWindowLimiter(IpKey(context), _ => SlidingWindow(limits.Value.Authorize)));
            limiter.OnRejected = (rejected, cancellationToken) =>
            {
                // A sliding window gives no retry time. The endpoint's own window is the longest wait, so it is safe.
                var policy = rejected.HttpContext.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName;
                var window = policy == LoginPolicy ? limits.Value.Login.Window : limits.Value.Authorize.Window;
                var retryAfter = rejected.Lease.TryGetMetadata(MetadataName.RetryAfter, out var wait) ? wait : window;
                return new ValueTask(WriteRejectedAsync(rejected.HttpContext, retryAfter));
            };
        });
        return services;
    }

    /// <summary>
    /// The partition key of a caller (<see cref="SourceKeys.For"/>). The address is the client's after the forwarded
    /// headers step, which trusts only configured proxies.
    /// </summary>
    public static string IpKey(HttpContext context) => SourceKeys.For(context.Connection.RemoteIpAddress);

    public static SlidingWindowRateLimiterOptions SlidingWindow(RateLimit limit) => new()
    {
        PermitLimit = limit.PermitLimit,
        Window = limit.Window,
        SegmentsPerWindow = 6,
        QueueLimit = 0,
    };

    /// <summary>
    /// 429 with <c>Retry-After</c>. The body uses <c>temporarily_unavailable</c> (RFC 6749, section 4.1.2.1), the closest
    /// OAuth error code; OAuth defines no code for rate limits. The response does not say which limit applied.
    /// </summary>
    public static Task WriteRejectedAsync(HttpContext context, TimeSpan? retryAfter)
    {
        OAuthResponses.NoStore(context.Response);
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (retryAfter is { } wait)
        {
            context.Response.Headers.RetryAfter = ((long)Math.Ceiling(wait.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        }

        context.Response.ContentType = "application/json";
        return context.Response.WriteAsync(JsonSerializer.Serialize(new { error = "temporarily_unavailable" }), context.RequestAborted);
    }
}
