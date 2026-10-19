using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;
using OpenTelemetry.Trace;

namespace Heimdall.IntegrationTests.Api;

/// <summary>OpenTelemetry: the data that leaves the server must follow D7, and the metric tags must stay bounded.</summary>
[Collection(PostgresGroup.Name)]
public sealed class TelemetryTests
{
    private const string SecretState = "state-value-that-must-not-leak";
    private const string SecretToken = "token-value-that-must-not-leak";

    private readonly PostgresFixture _postgres;

    public TelemetryTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task Traces_hold_no_query_values_and_no_authorization_header()
    {
        var activities = new List<Activity>();
        await using var api = new HeimdallApiFactory(_postgres);
        await using var traced = api.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.ConfigureOpenTelemetryTracerProvider(tracing => tracing.AddInMemoryExporter(activities))));
        var tenant = await api.AddTenantAsync();
        using var http = traced.CreateClient(new() { BaseAddress = new Uri($"https://{tenant.Host}/"), AllowAutoRedirect = false });

        using (await http.GetAsync($"oauth/v1/authorize?client_id=unknown&state={SecretState}")) { }
        using (var request = new HttpRequestMessage(HttpMethod.Get, "oauth/v1/userinfo"))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", SecretToken);
            using (await http.SendAsync(request)) { }
        }

        // The server span of each request is exported when the request ends.
        Assert.Contains(activities, a => a.Kind == ActivityKind.Server && a.DisplayName.Contains("authorize", StringComparison.Ordinal));
        var values = activities.SelectMany(a => a.TagObjects).Select(t => t.Value?.ToString() ?? string.Empty).ToList();
        Assert.DoesNotContain(values, v => v.Contains(SecretState, StringComparison.Ordinal));
        Assert.DoesNotContain(values, v => v.Contains(SecretToken, StringComparison.Ordinal));
    }

    [DockerFact]
    public async Task Token_metrics_have_bounded_tags()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var collector = new MetricCollector<long>(
            api.Services.GetRequiredService<IMeterFactory>(), HeimdallMetrics.MeterName, "heimdall.token.requests");
        using var http = api.ClientFor(tenant.Host);

        using (var ok = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token") { Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]) })
        {
            ok.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, tenant.ClientSecret);
            using var response = await http.SendAsync(ok);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        // An attacker chooses the grant_type value. It must not become a new tag value.
        using (await http.PostAsync("oauth/v1/token", new FormUrlEncodedContent([new("grant_type", "attacker-chosen-" + Guid.NewGuid())]))) { }

        var measurements = collector.GetMeasurementSnapshot();
        Assert.Contains(measurements, m => (string?)m.Tags["grant_type"] == "client_credentials" && (string?)m.Tags["outcome"] == "success");
        Assert.Contains(measurements, m => (string?)m.Tags["grant_type"] == "other" && (string?)m.Tags["outcome"] == "unsupported_grant_type");
        Assert.DoesNotContain(measurements, m => ((string?)m.Tags["grant_type"])!.StartsWith("attacker", StringComparison.Ordinal));
    }

    [DockerFact]
    public async Task Failed_sign_ins_are_counted()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddUserAsync(tenant, "alice@example.com", "correct horse battery staple");
        using var collector = new MetricCollector<long>(
            api.Services.GetRequiredService<IMeterFactory>(), HeimdallMetrics.MeterName, "heimdall.login.attempts");
        using var browser = new BrowserSession(api, tenant.Host);

        using (await browser.LoginAsync("alice@example.com", "wrong password value")) { }
        using (await browser.LoginAsync("alice@example.com", "correct horse battery staple")) { }

        var outcomes = collector.GetMeasurementSnapshot().Select(m => (string?)m.Tags["outcome"]).ToList();
        Assert.Equal(["failure", "success"], outcomes);
    }
}
