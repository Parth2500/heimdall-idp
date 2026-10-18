namespace Heimdall.Api.Hosting;

/// <summary>
/// Headers on every response. Heimdall serves JSON only today, so the policy allows nothing to load and no page to
/// frame it (threat model, login, Tampering: clickjacking). The Angular pages get their own policy when they arrive.
/// </summary>
internal sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";
        headers.XFrameOptions = "DENY";
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        return _next(context);
    }
}
