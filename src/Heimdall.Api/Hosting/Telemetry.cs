using Heimdall.Infrastructure.Telemetry;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Heimdall.Api.Hosting;

/// <summary>
/// OpenTelemetry traces and metrics. Sources: ASP.NET Core, the .NET runtime, Npgsql (connection pool and commands), and
/// <see cref="HeimdallMetrics"/>. An OTLP exporter starts only when <c>OTEL_EXPORTER_OTLP_ENDPOINT</c> is set, so a
/// developer machine sends nothing anywhere.
/// </summary>
/// <remarks>
/// D7 applies to telemetry too. Heimdall removes the query string from every server span, so a <c>state</c>, a
/// challenge, or a token in a query never reaches a trace. It records no headers, so no Authorization header or
/// cookie. Npgsql records the SQL text, and every value in Heimdall's SQL is a parameter, so no value reaches a trace.
/// </remarks>
internal static class Telemetry
{
    public const string ServiceName = "heimdall";

    public static IServiceCollection AddHeimdallTelemetry(this IServiceCollection services, IConfiguration configuration)
    {
        var builder = services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService(ServiceName))
            .WithTracing(tracing => tracing
                .AddAspNetCoreInstrumentation(options =>
                {
                    // Probes run every few seconds and tell nothing about users. Leave them out of traces.
                    options.Filter = context => !context.Request.Path.StartsWithSegments("/health", StringComparison.Ordinal);

                    // The instrumentation redacts query values by default, but an environment variable can turn that off.
                    // Heimdall removes the query tag itself, so no setting can put a state or a token into a trace.
                    options.EnrichWithHttpRequest = (activity, _) => activity.SetTag("url.query", null);
                })
                .AddSource("Npgsql"))
            .WithMetrics(metrics => metrics
                .AddAspNetCoreInstrumentation()
                .AddRuntimeInstrumentation()
                .AddMeter("Npgsql", HeimdallMetrics.MeterName));

        if (!string.IsNullOrWhiteSpace(configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
        {
            builder.UseOtlpExporter();
        }

        return services;
    }
}
