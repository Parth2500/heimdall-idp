using Heimdall.Infrastructure;
using Heimdall.Infrastructure.Development;

var builder = WebApplication.CreateBuilder(args);

// The password is not in any appsettings file. Set it with user-secrets or the PGPASSWORD environment variable.
var connectionString = builder.Configuration.GetConnectionString("Heimdall")
    ?? throw new InvalidOperationException("The connection string 'ConnectionStrings:Heimdall' is not set.");

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHeimdallInfrastructure(connectionString);

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

    if (!result.Created)
    {
        Console.WriteLine($"Development data already exists (tenant {result.TenantHost}, client {result.ClientId}).");
        Console.WriteLine("The client secret was shown only once, when it was created.");
        return 0;
    }

    Console.WriteLine("Development data created. The secret is shown only now. Heimdall stores only its hash.");
    Console.WriteLine($"  tenant host:   {result.TenantHost}");
    Console.WriteLine($"  client_id:     {result.ClientId}");
    Console.WriteLine($"  client_secret: {result.ClientSecret}");
    Console.WriteLine($"  audience:      {result.Audience}");
    return 0;
}
