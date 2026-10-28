using Microsoft.OpenApi;
using Scalar.AspNetCore;

namespace Heimdall.Api.Hosting;

/// <summary>
/// The OpenAPI 3.1 document of the session API (<c>/session/v1</c>) and the Scalar page that shows it (issue #22).
/// Development only: a production server does not describe its internal browser API to everyone.
/// </summary>
/// <remarks>
/// The OAuth and OpenID Connect endpoints are not in the document. Their contract is the RFCs and the discovery
/// document. The Angular account pages are the only client of the session API, and they can generate their client
/// from this document.
/// </remarks>
internal static class ApiDocumentation
{
    public const string DocumentPath = "/openapi/v1.json";
    public const string PagePath = "/scalar";

    // The Scalar page sets its configuration and styles inline, and it shows images as data: URLs. The policy allows
    // that for this page only. It is never served outside Development. Fonts stay local (no Google Fonts call).
    private const string PagePolicy =
        "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    public static void AddHeimdallApiDocumentation(this IServiceCollection services, IHostEnvironment environment)
    {
        if (!environment.IsDevelopment())
        {
            return;
        }

        services.AddOpenApi(options =>
        {
            options.ShouldInclude = description =>
                description.RelativePath?.StartsWith("session/v1/", StringComparison.Ordinal) == true;
            options.AddDocumentTransformer((document, _, _) =>
            {
                document.Info = new OpenApiInfo
                {
                    Title = "Heimdall session API",
                    Version = "v1",
                    Description =
                        "The browser API of the account pages, on each tenant origin. Every request that changes state " +
                        "needs the antiforgery token from GET /session/v1/csrf in the X-XSRF-TOKEN header, a JSON body, " +
                        "and no foreign Origin header. Same origin only: Heimdall sends no CORS headers here.",
                };
                return Task.CompletedTask;
            });
        });
    }

    public static void MapHeimdallApiDocumentation(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            return;
        }

        app.MapOpenApi(DocumentPath);
        app.MapScalarApiReference(PagePath, options => options
                .WithTitle("Heimdall session API")
                .WithOpenApiRoutePattern(DocumentPath)
                .DisableDefaultFonts())
            .AddEndpointFilter(async (context, next) =>
            {
                context.HttpContext.Response.Headers.ContentSecurityPolicy = PagePolicy;
                return await next(context).ConfigureAwait(false);
            });
    }
}
