using Heimdall.Application;
using Heimdall.Application.Keys;
using Heimdall.Domain.Keys;
using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Development;

var builder = WebApplication.CreateBuilder(args);

// The password is not in any appsettings file. Set it with user-secrets or the PGPASSWORD environment variable.
var connectionString = builder.Configuration.GetConnectionString("Heimdall")
    ?? throw new InvalidOperationException("The connection string 'ConnectionStrings:Heimdall' is not set.");

var keyOptions = builder.Configuration.GetSection(SigningKeyOptions.SectionName).Get<SigningKeyOptions>() ?? new SigningKeyOptions();
var keyErrors = keyOptions.Validate();
if (keyErrors.Count > 0)
{
    throw new InvalidOperationException("Invalid signing key settings: " + string.Join(" ", keyErrors));
}

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(keyOptions);
builder.Services.AddHeimdallApplication();
builder.Services.AddHeimdallInfrastructure(connectionString);

// The development key file holds plain private keys. It is allowed only in Development. No production key store
// (Key Vault or KMS) exists yet, so the server does not start in any other environment.
if (builder.Environment.IsDevelopment())
{
    var keyFile = builder.Configuration[$"{SigningKeyOptions.SectionName}:DevelopmentKeyFile"] ?? ".local/signing-keys.json";
    builder.Services.AddDevelopmentKeyFile(Path.Combine(builder.Environment.ContentRootPath, keyFile));
}
else
{
    throw new InvalidOperationException(
        "No key store is configured for this environment. The development key file runs only in Development.");
}

var app = builder.Build();

if (args.Contains("seed-dev", StringComparer.Ordinal))
{
    return await SeedDevelopmentDataAsync(app);
}

app.MapGet("/", () => "Heimdall");

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
        // The key waits one JWKS cache lifetime before it signs. Nothing activates it automatically yet.
        Console.WriteLine($"  The key can sign from {result.SigningFrom:u}. Run seed-dev again after that time to activate it.");
    }

    return 0;
}
