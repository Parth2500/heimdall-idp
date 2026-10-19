using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Heimdall.IntegrationTests.Api;

/// <summary><c>/health/live</c> and <c>/health/ready</c>, as an orchestrator probe calls them: plain HTTP, no tenant host.</summary>
[Collection(PostgresGroup.Name)]
public sealed class HealthTests
{
    private readonly PostgresFixture _postgres;

    public HealthTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static async Task AssertBodyAsync(HttpResponseMessage response, HttpStatusCode status, string body)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(body, await response.Content.ReadAsStringAsync());
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [DockerFact]
    public async Task Probes_work_over_plain_http_on_any_host()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        using var http = api.ClientFor("10.0.0.7", scheme: "http");

        using var live = await http.GetAsync("health/live");
        using var ready = await http.GetAsync("health/ready");

        await AssertBodyAsync(live, HttpStatusCode.OK, "Healthy");
        await AssertBodyAsync(ready, HttpStatusCode.OK, "Healthy");
    }

    [DockerFact]
    public async Task Without_the_database_the_server_is_live_but_not_ready()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        await using var broken = api.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration(configuration =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Nothing listens on port 1, so the connection fails at once.
                ["ConnectionStrings:Heimdall"] = "Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none;Timeout=2",
            })));
        using var http = broken.CreateClient(new() { BaseAddress = new Uri("http://10.0.0.7/") });

        using var live = await http.GetAsync("health/live");
        using var ready = await http.GetAsync("health/ready");

        await AssertBodyAsync(live, HttpStatusCode.OK, "Healthy");

        // One word: the reason stays on the server.
        await AssertBodyAsync(ready, HttpStatusCode.ServiceUnavailable, "Unhealthy");
    }

    [DockerFact]
    public async Task With_a_management_port_the_public_port_has_no_health_endpoint()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        await using var restricted = api.WithWebHostBuilder(builder => builder.UseSetting("Heimdall:Health:Port", "8081"));
        using var http = restricted.CreateClient(new() { BaseAddress = new Uri("https://unknown.example.com/") });

        using var response = await http.GetAsync("health/ready");

        // The request falls through to tenant resolution, which knows no such host.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
