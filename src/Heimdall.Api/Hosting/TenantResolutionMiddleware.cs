using Heimdall.Api.Endpoints;
using Heimdall.Application.Common;
using Heimdall.Application.Tenants;
using Heimdall.Domain.Tenants;
using Heimdall.Infrastructure.Persistence;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Hosting;

/// <summary>
/// Runs before every endpoint. It rejects plain HTTP (D1), then finds the tenant from the host name (D21) and sets
/// the tenant of the database context (D20). Every endpoint belongs to a tenant, so an unknown host gets 404.
/// </summary>
internal sealed partial class TenantResolutionMiddleware
{
    private const string TenantItem = "Heimdall.Tenant";

    private readonly RequestDelegate _next;
    private readonly ITenantDirectory _tenants;
    private readonly ILogger<TenantResolutionMiddleware> _logger;

    public TenantResolutionMiddleware(RequestDelegate next, ITenantDirectory tenants, ILogger<TenantResolutionMiddleware> logger)
    {
        _next = next;
        _tenants = tenants;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, TenantScope scope)
    {
        // Reject, do not redirect. A redirect of a token request comes after the secret already crossed the network.
        if (!context.Request.IsHttps)
        {
            LogPlainHttp(_logger);
            await OAuthResponses.WriteErrorAsync(context, OAuthError.InvalidRequest("plain http")).ConfigureAwait(false);
            return;
        }

        var host = context.Request.Host.Host.TrimEnd('.').ToLowerInvariant();
        var tenant = await _tenants.FindByHostAsync(host, context.RequestAborted).ConfigureAwait(false);
        if (tenant is null)
        {
            // The same empty 404 as an unknown path, so a caller cannot learn which tenants exist.
            LogUnknownHost(_logger);
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        scope.Set(tenant.Id);
        context.Items[TenantItem] = tenant;
        await _next(context).ConfigureAwait(false);
    }

    /// <summary>The facts about this request that a use case needs.</summary>
    public static RequestContext GetRequestContext(HttpContext context)
    {
        var tenant = context.Items[TenantItem] as Tenant
            ?? throw new InvalidOperationException("The tenant is not resolved. The middleware must run first.");
        var issuer = context.RequestServices.GetRequiredService<IOptions<IssuerOptions>>().Value.IssuerFor(tenant.Host);

        // Behind a proxy, RemoteIpAddress is the proxy. Forwarded headers come with the deployment decision.
        return new RequestContext(tenant, issuer, context.TraceIdentifier, context.Connection.RemoteIpAddress);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Request refused: plain HTTP.")]
    private static partial void LogPlainHttp(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Request refused: unknown tenant host.")]
    private static partial void LogUnknownHost(ILogger logger);
}
