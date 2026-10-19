using Heimdall.Api.Endpoints;
using Heimdall.Api.Hosting;
using Heimdall.Api.Jobs;
using Heimdall.Application;
using Heimdall.Application.Keys;
using Heimdall.Application.Settings;
using Heimdall.Application.Users;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Development;
using Heimdall.Infrastructure.Keys;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Purge;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Structured logs. Each line carries the correlation ID as a scope value (D7).
if (builder.Environment.IsDevelopment())
{
    builder.Logging.AddSimpleConsole(options => options.IncludeScopes = true);
}
else
{
    builder.Logging.AddJsonConsole(options =>
    {
        options.IncludeScopes = true;
        options.UseUtcTimestamp = true;
    });
}

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 64 * 1024;
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHeimdallTelemetry(builder.Configuration);

builder.Services.AddOptions<SigningKeyOptions>()
    .Bind(builder.Configuration.GetSection(SigningKeyOptions.SectionName))
    .Validate(options => options.Validate().Count == 0, "Invalid settings in " + SigningKeyOptions.SectionName + ".")
    .ValidateOnStart();
builder.Services.AddSingleton(provider => provider.GetRequiredService<IOptions<SigningKeyOptions>>().Value);
builder.Services.AddOptions<IssuerOptions>().Bind(builder.Configuration.GetSection(IssuerOptions.SectionName));
builder.Services.AddOptions<UiOptions>().Bind(builder.Configuration.GetSection(UiOptions.SectionName));

// D16: the platform limits. A minimum of zero, or a minimum above its maximum, stops the server at startup.
builder.Services.AddOptions<PlatformLimits>()
    .Bind(builder.Configuration.GetSection(PlatformLimits.SectionName))
    .Validate(limits => limits.Validate().Count == 0, "Invalid settings in " + PlatformLimits.SectionName + ".")
    .ValidateOnStart();
builder.Services.AddSingleton(provider => provider.GetRequiredService<IOptions<PlatformLimits>>().Value);

builder.Services.AddOptions<PasswordHashingOptions>()
    .Bind(builder.Configuration.GetSection(PasswordHashingOptions.SectionName))
    .Validate(options => options.Validate().Count == 0, "Invalid settings in " + PasswordHashingOptions.SectionName + ".")
    .ValidateOnStart();
builder.Services.AddSingleton(provider => provider.GetRequiredService<IOptions<PasswordHashingOptions>>().Value);

// The password is not in any appsettings file. Set it with user-secrets or an environment variable.
builder.Services.AddHeimdallApplication();
builder.Services.AddHeimdallInfrastructure(
    provider => provider.GetRequiredService<IConfiguration>().GetConnectionString("Heimdall")
        ?? throw new InvalidOperationException("The connection string 'ConnectionStrings:Heimdall' is not set."),

    // The platform jobs (key job tenant list, purge) need a role in heimdall_platform. Without this setting they use
    // the application connection, which sees every tenant only when its role bypasses row-level security.
    provider => provider.GetRequiredService<IConfiguration>().GetConnectionString("HeimdallPlatform")
        ?? provider.GetRequiredService<IConfiguration>().GetConnectionString("Heimdall")
        ?? throw new InvalidOperationException("The connection string 'ConnectionStrings:Heimdall' is not set."));

// The development key file holds plain private keys. It is allowed only in Development. No production key store
// (Key Vault or KMS) exists yet, so the server does not start in any other environment. See the check after Build.
builder.Services.AddSingleton<IKeyMaterialStore>(provider =>
{
    var environment = provider.GetRequiredService<IHostEnvironment>();
    if (!environment.IsDevelopment())
    {
        throw new InvalidOperationException(
            "No key store is configured for this environment. The development key file runs only in Development.");
    }

    var path = provider.GetRequiredService<IConfiguration>()[$"{SigningKeyOptions.SectionName}:DevelopmentKeyFile"]
        ?? ".local/signing-keys.json";
    return new DevelopmentKeyFile(Path.Combine(environment.ContentRootPath, path));
});

// Antiforgery for the login API. Angular's HttpClient reads the request token cookie and sends the header.
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = SessionEndpoints.AntiforgeryCookie;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.HeaderName = SessionEndpoints.XsrfHeader;
});

builder.Services.AddOptions<ProxyOptions>()
    .Bind(builder.Configuration.GetSection(ProxyOptions.SectionName))
    .Validate(options => options.Validate().Count == 0, "Invalid settings in " + ProxyOptions.SectionName + ".")
    .ValidateOnStart();
builder.Services.AddHeimdallRateLimits(builder.Configuration);
builder.Services.AddOptions<HealthOptions>().Bind(builder.Configuration.GetSection(HealthOptions.SectionName));
builder.Services.AddHeimdallHealthChecks();

builder.Services.AddOptions<BackgroundJobOptions>().Bind(builder.Configuration.GetSection(BackgroundJobOptions.SectionName));
builder.Services.AddSingleton<SigningKeyJob>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<SigningKeyJob>());

builder.Services.AddOptions<PurgeOptions>()
    .Bind(builder.Configuration.GetSection(PurgeOptions.SectionName))
    .Validate(options => options.Validate().Count == 0, "Invalid settings in " + PurgeOptions.SectionName + ".")
    .ValidateOnStart();
builder.Services.AddSingleton(provider => provider.GetRequiredService<IOptions<PurgeOptions>>().Value);
builder.Services.AddHostedService<PurgeJob>();

var app = builder.Build();

// Fail at startup, not at the first request: no key store, or no connection string.
_ = app.Services.GetRequiredService<IKeyMaterialStore>();
_ = app.Configuration.GetConnectionString("Heimdall")
    ?? throw new InvalidOperationException("The connection string 'ConnectionStrings:Heimdall' is not set.");

if (args.Contains("seed-dev", StringComparer.Ordinal))
{
    return await SeedDevelopmentDataAsync(app);
}

if (args.Length > 0 && args[0] == "remove-key")
{
    return await RemoveCompromisedKeyAsync(app, args);
}

// First: every later step (HTTPS check, audit source IP) must see the client, not the proxy. Only configured proxies
// are trusted. Without any, forwarded headers are ignored.
var proxies = app.Services.GetRequiredService<IOptions<ProxyOptions>>().Value;
if (proxies.IsEnabled)
{
    app.UseForwardedHeaders(proxies.ToMiddlewareOptions());
}

// The developer exception page shows details in Development only. Elsewhere a failure is an empty 500.
app.UseExceptionHandler(failure => failure.Run(context =>
{
    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
    return Task.CompletedTask;
}));

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<CorrelationIdMiddleware>();

// Before tenant resolution and the HTTPS check: probes call the container IP over plain HTTP.
app.UseHeimdallHealthChecks(app.Services.GetRequiredService<IOptions<HealthOptions>>().Value);
app.UseMiddleware<TenantResolutionMiddleware>();

// After tenant resolution: an unknown host or plain HTTP is refused before it uses a permit.
app.UseRateLimiter();

app.MapPost(TokenEndpoint.Path, TokenEndpoint.HandleAsync);
app.MapPost(RevokeEndpoint.Path, RevokeEndpoint.HandleAsync);
app.MapGet(WellKnownEndpoints.DiscoveryPath, WellKnownEndpoints.DiscoveryAsync);
app.MapGet(WellKnownEndpoints.JwksPath, WellKnownEndpoints.JwksAsync);
SessionEndpoints.Map(app);
AuthorizeEndpoint.Map(app);
UserInfoApiEndpoint.Map(app);

await app.RunAsync();
return 0;

static async Task<int> SeedDevelopmentDataAsync(WebApplication app)
{
    // The seed creates a known tenant and client. It must never run against a real environment.
    if (!app.Environment.IsDevelopment())
    {
        await Console.Error.WriteLineAsync("seed-dev runs only when ASPNETCORE_ENVIRONMENT is Development.");
        return 1;
    }

    using var scope = app.Services.CreateScope();
    var result = await scope.ServiceProvider.GetRequiredService<DevelopmentSeeder>().SeedAsync(CancellationToken.None);

    if (result.Created)
    {
        Console.WriteLine("Development data created. The secret is shown only now. Heimdall stores only its hash.");
        Console.WriteLine($"  tenant host:   {result.TenantHost}");
        Console.WriteLine($"  client_id:     {result.ClientId}");
        Console.WriteLine($"  client_secret: {result.ClientSecret}");
        Console.WriteLine($"  audience:      {result.Audience}");
    }

    if (result.UserPassword is not null)
    {
        Console.WriteLine("Development user created. The password is shown only now. Heimdall stores only its Argon2id hash.");
        Console.WriteLine($"  email:         {result.UserEmail}");
        Console.WriteLine($"  password:      {result.UserPassword}");
    }
    else
    {
        Console.WriteLine($"Development data already exists (tenant {result.TenantHost}, client {result.ClientId}).");
        Console.WriteLine("The client secret was shown only once, when it was created.");
    }

    Console.WriteLine($"  signing key:   {result.Kid} ({result.KeyStatus.ToString().ToLowerInvariant()})");
    if (result.KeyStatus == SigningKeyStatus.Pending)
    {
        Console.WriteLine($"  The key can sign from {result.SigningFrom:u}. The running server activates it then.");
    }

    return 0;
}

// Emergency procedure (threat model, JWKS, Elevation of privilege): remove-key <tenant host> <kid>.
// The admin portal (Phase 3) replaces this command. It runs in any environment, with the operator's database access.
static async Task<int> RemoveCompromisedKeyAsync(WebApplication app, string[] args)
{
    if (args.Length != 3)
    {
        await Console.Error.WriteLineAsync("Usage: remove-key <tenant host> <kid>");
        return 2;
    }

    using var scope = app.Services.CreateScope();
    var host = args[1].Trim().ToLowerInvariant();
    var tenantId = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().Tenants
        .Where(t => t.Host == host)
        .Select(t => (Guid?)t.Id)
        .SingleOrDefaultAsync();
    if (tenantId is not { } id)
    {
        await Console.Error.WriteLineAsync($"No tenant has the host '{host}'.");
        return 1;
    }

    scope.ServiceProvider.GetRequiredService<TenantScope>().Set(id);
    var result = await scope.ServiceProvider.GetRequiredService<SigningKeyService>()
        .RemoveCompromisedKeyAsync(id, args[2], "cli-remove-key-" + Guid.NewGuid().ToString("N"), CancellationToken.None);

    if (!result.Found)
    {
        await Console.Error.WriteLineAsync($"Tenant '{host}' has no key with kid '{args[2]}'.");
        return 1;
    }

    Console.WriteLine($"Key {args[2]} is out of the JWKS. Tokens it signed no longer verify.");
    if (result.WasActive)
    {
        Console.WriteLine($"It was the active key. Replacement: {result.Replacement.ToString().ToLowerInvariant()}.");
        Console.WriteLine("Token issuance stops until the replacement key is active (one publish wait).");
        Console.WriteLine("Running servers stop using the removed key within one server cache lifetime.");
    }

    return 0;
}

/// <summary>The entry point. Public so that the API tests can host it.</summary>
public partial class Program;
