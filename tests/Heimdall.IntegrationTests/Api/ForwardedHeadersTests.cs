using System.Net;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// Forwarded headers (threat model, Tenants and client configuration, forwarded headers rows). The test server has no
/// network connection, so a startup filter sets the connection address to <see cref="ProxyIp"/>.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class ForwardedHeadersTests
{
    private const string ProxyIp = "10.0.0.5";
    private const string ClientIp = "203.0.113.9";

    private readonly PostgresFixture _postgres;

    public ForwardedHeadersTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    /// <summary>The connection comes from <see cref="ProxyIp"/>, as it would behind a reverse proxy.</summary>
    private sealed class FromProxy : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(ProxyIp);
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    private static WebApplicationFactory<Program> Host(HeimdallApiFactory api, string? knownProxy) =>
        api.WithWebHostBuilder(builder =>
        {
            builder.ConfigureTestServices(services => services.AddSingleton<IStartupFilter, FromProxy>());
            if (knownProxy is not null)
            {
                builder.UseSetting("Heimdall:ForwardedHeaders:KnownProxies:0", knownProxy);
            }
        });

    /// <summary>A client_credentials request with forwarded headers. Returns the status and the audited source IP.</summary>
    private static async Task<(HttpStatusCode Status, string? SourceIp)> TokenRequestAsync(
        HeimdallApiFactory api,
        WebApplicationFactory<Program> host,
        TestTenant tenant,
        string scheme,
        string forwardedFor,
        string? forwardedHost = null)
    {
        using var http = host.CreateClient(new() { BaseAddress = new Uri($"{scheme}://{tenant.Host}/") });
        using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
        {
            Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]),
        };
        request.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, tenant.ClientSecret);
        request.Headers.Add("X-Forwarded-For", forwardedFor);
        request.Headers.Add("X-Forwarded-Proto", "https");
        if (forwardedHost is not null)
        {
            request.Headers.Add("X-Forwarded-Host", forwardedHost);
        }

        using var response = await http.SendAsync(request);

        await using var scope = api.Services.CreateAsyncScope();
        var audit = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking()
            .Where(e => e.TenantId == tenant.Tenant.Id && e.Type == AuditEventTypes.TokenIssued)
            .OrderByDescending(e => e.OccurredAt)
            .FirstOrDefaultAsync();
        return (response.StatusCode, audit?.SourceIp?.ToString());
    }

    [DockerFact]
    public async Task A_trusted_proxy_gives_the_client_address_and_the_original_scheme()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var host = Host(api, knownProxy: ProxyIp);

        // TLS ends at the proxy, so the hop to Heimdall is plain HTTP.
        var (status, sourceIp) = await TokenRequestAsync(api, host, tenant, "http", ClientIp);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(ClientIp, sourceIp);
    }

    [DockerFact]
    public async Task A_client_cannot_choose_its_address_by_adding_to_the_header()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var host = Host(api, knownProxy: ProxyIp);

        // The client sent "1.2.3.4". The proxy appended the real address on the right. Only the last hop counts.
        var (_, sourceIp) = await TokenRequestAsync(api, host, tenant, "http", "1.2.3.4, " + ClientIp);

        Assert.Equal(ClientIp, sourceIp);
    }

    [DockerFact]
    public async Task Headers_from_an_unknown_address_are_ignored()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var other = Host(api, knownProxy: "10.0.0.6");
        var none = Host(api, knownProxy: null);

        // X-Forwarded-Proto is ignored, so plain HTTP is refused.
        var (plainStatus, _) = await TokenRequestAsync(api, other, tenant, "http", ClientIp);

        // Over HTTPS the request works, and the audit has the connection address, not the claimed one.
        var (status, sourceIp) = await TokenRequestAsync(api, none, tenant, "https", ClientIp);

        Assert.Equal(HttpStatusCode.BadRequest, plainStatus);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(ProxyIp, sourceIp);
    }

    [DockerFact]
    public async Task Forwarded_host_never_chooses_the_tenant()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        var otherTenant = await api.AddTenantAsync();
        var host = Host(api, knownProxy: ProxyIp);

        // Tenant A's credentials, with a forwarded host of tenant B. The Host header still decides: tenant A.
        var (status, _) = await TokenRequestAsync(api, host, tenant, "http", ClientIp, forwardedHost: otherTenant.Host);

        Assert.Equal(HttpStatusCode.OK, status);
    }
}
