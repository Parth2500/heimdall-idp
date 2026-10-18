using Heimdall.Api.Endpoints;
using Heimdall.Api.Hosting;
using Heimdall.Api.Jobs;
using Heimdall.Application;
using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Development;
using Heimdall.Infrastructure.Keys;
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

builder.Services.AddOptions<SigningKeyOptions>()
    .Bind(builder.Configuration.GetSection(SigningKeyOptions.SectionName))
    .Validate(options => options.Validate().Count == 0, "Invalid settings in " + SigningKeyOptions.SectionName + ".")
    .ValidateOnStart();
builder.Services.AddSingleton(provider => provider.GetRequiredService<IOptions<SigningKeyOptions>>().Value);
builder.Services.AddOptions<IssuerOptions>().Bind(builder.Configuration.GetSection(IssuerOptions.SectionName));

// The password is not in any appsettings file. Set it with user-secrets or an environment variable.
builder.Services.AddHeimdallApplication();
builder.Services.AddHeimdallInfrastructure(provider =>
    provider.GetRequiredService<IConfiguration>().GetConnectionString("Heimdall")
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

builder.Services.AddSingleton<SigningKeyActivationJob>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<SigningKeyActivationJob>());

var app = builder.Build();

// Fail at startup, not at the first request: no key store, or no connection string.
_ = app.Services.GetRequiredService<IKeyMaterialStore>();
_ = app.Configuration.GetConnectionString("Heimdall")
    ?? throw new InvalidOperationException("The connection string 'ConnectionStrings:Heimdall' is not set.");

if (args.Contains("seed-dev", StringComparer.Ordinal))
{
    return await SeedDevelopmentDataAsync(app);
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

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<TenantResolutionMiddleware>();

app.MapPost(TokenEndpoint.Path, TokenEndpoint.HandleAsync);
app.MapGet(WellKnownEndpoints.DiscoveryPath, WellKnownEndpoints.DiscoveryAsync);
app.MapGet(WellKnownEndpoints.JwksPath, WellKnownEndpoints.JwksAsync);

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

/// <summary>The entry point. Public so that the API tests can host it.</summary>
public partial class Program;
