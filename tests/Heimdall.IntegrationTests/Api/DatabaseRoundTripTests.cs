using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Heimdall.Infrastructure.Stores;
using Xunit.Abstractions;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// A budget for the database work of each endpoint (#15). Each connection open costs one extra <c>set_config</c> round
/// trip for row-level security, so the budget counts opens on the request path. Audit writes are counted apart: they
/// share the audit writer's transactions. The second request of each kind is the one counted, so caches are warm.
/// </summary>
/// <remarks>A change that adds round trips fails here. The test output lists the SQL of each counted request.</remarks>
[Collection(PostgresGroup.Name)]
public sealed class DatabaseRoundTripTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;
    private readonly ITestOutputHelper _output;

    public DatabaseRoundTripTests(PostgresFixture postgres, ITestOutputHelper output)
    {
        _postgres = postgres;
        _output = output;
    }

    /// <summary>Counts EF Core connection opens and executed commands while it is active.</summary>
    private sealed class DbCounter : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IDisposable
    {
        private readonly List<IDisposable> _subscriptions = [];
        private int _opens;
        private int _commands;

        public DbCounter() => _subscriptions.Add(DiagnosticListener.AllListeners.Subscribe(this));

        public bool Counting { get; set; }

        public ConcurrentQueue<string> Log { get; } = new();

        public (int Opens, int Commands) Take()
        {
            var result = (Interlocked.Exchange(ref _opens, 0), Interlocked.Exchange(ref _commands, 0));
            return result;
        }

        public void OnNext(DiagnosticListener listener)
        {
            if (listener.Name == DbLoggerCategory.Name)
            {
                _subscriptions.Add(listener.Subscribe(this));
            }
        }

        public void OnNext(KeyValuePair<string, object?> value)
        {
            if (!Counting)
            {
                return;
            }

            if (value.Key == RelationalEventId.ConnectionOpened.Name)
            {
                Interlocked.Increment(ref _opens);
            }
            else if (value.Key == RelationalEventId.CommandExecuted.Name)
            {
                Interlocked.Increment(ref _commands);
                if (value.Value is CommandExecutedEventData data)
                {
                    Log.Enqueue(data.Command.CommandText.ReplaceLineEndings(" ")[..Math.Min(110, data.Command.CommandText.Length)]);
                }
            }
            else if (value.Key == RelationalEventId.TransactionStarted.Name)
            {
                Log.Enqueue("BEGIN");
            }
            else if (value.Key == RelationalEventId.TransactionCommitted.Name)
            {
                Log.Enqueue("COMMIT");
            }
        }

        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void Dispose() => _subscriptions.ForEach(s => s.Dispose());
    }

    [DockerFact]
    public async Task Each_endpoint_stays_within_its_database_budget()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant);
        await api.AddUserAsync(tenant, Email, Password);
        using var http = api.ClientFor(tenant.Host);
        using var counter = new DbCounter();
        var results = new ConcurrentDictionary<string, (int Opens, int Commands, int AuditCommits)>();
        var audit = api.Services.GetRequiredService<BatchingAuditLog>();

        var commitsBefore = 0;

        async Task Measure(string name, Func<Task> request)
        {
            await request(); // warm the caches
            counter.Take();
            commitsBefore = audit.Commits;
            counter.Counting = true;
            await request();
            counter.Counting = false;

            // The audit writer runs on its own connection: one open and one insert command for each commit.
            var (opens, commands) = counter.Take();
            var commits = audit.Commits - commitsBefore;
            results[name] = (opens - commits, commands - commits, commits);
            _output.WriteLine("== " + name);
            while (counter.Log.TryDequeue(out var line))
            {
                _output.WriteLine("   " + line);
            }
        }

        await Measure("POST /token client_credentials", async () =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "oauth/v1/token")
            {
                Content = new FormUrlEncodedContent([new("grant_type", "client_credentials")]),
            };
            request.Headers.Authorization = HeimdallApiFactory.Basic(tenant.ClientId, tenant.ClientSecret);
            using var response = await http.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        });

        using var browser = new BrowserSession(api, tenant.Host);
        await Measure("POST /session/v1/login", async () =>
        {
            using var login = await browser.LoginAsync(Email, Password);
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        });

        string code = string.Empty;
        await Measure("GET /authorize (signed in)", async () =>
        {
            using var authorize = await browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = "web-app",
                ["redirect_uri"] = Callback,
                ["scope"] = "openid offline_access",
                ["code_challenge"] = Challenge,
                ["code_challenge_method"] = "S256",
            }));
            Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
            var location = authorize.Headers.Location!.OriginalString;
            code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();
        });

        string refresh = string.Empty;
        string access = string.Empty;
        var codes = new Queue<string>();
        await Measure("POST /token authorization_code", async () =>
        {
            using var authorize = await browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = "web-app",
                ["redirect_uri"] = Callback,
                ["scope"] = "openid offline_access",
                ["code_challenge"] = Challenge,
                ["code_challenge_method"] = "S256",
            }));
            var location = authorize.Headers.Location!.OriginalString;
            var fresh = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();

            // Only the redemption is counted: the authorize call above ran before the counter started, on the first
            // pass; on the counted pass its work is subtracted below.
            counter.Counting = false;
            counter.Take();
            counter.Log.Clear();
            commitsBefore = audit.Commits;
            counter.Counting = true;

            using var response = await http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("code", fresh),
                new("code_verifier", Verifier),
                new("redirect_uri", Callback),
                new("client_id", "web-app"),
                new("resource", tenant.Issuer + "/oauth/v1/userinfo"),
            ]));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            refresh = body.GetProperty("refresh_token").GetString()!;
            access = body.GetProperty("access_token").GetString()!;
        });

        await Measure("POST /token refresh_token", async () =>
        {
            using var response = await http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
            [
                new("grant_type", "refresh_token"),
                new("refresh_token", refresh),
                new("client_id", "web-app"),
                new("resource", tenant.Issuer + "/oauth/v1/userinfo"),
            ]));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            refresh = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("refresh_token").GetString()!;
        });

        await Measure("GET /userinfo", async () =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "oauth/v1/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
            using var response = await http.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        });

        await Measure("POST /revoke", async () =>
        {
            using var response = await http.PostAsync("oauth/v1/revoke", new FormUrlEncodedContent(
            [
                new("token", refresh),
                new("client_id", "web-app"),
            ]));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        });

        _output.WriteLine($"{"Endpoint",-36} {"Opens",6} {"Commands",9} {"Audit commits",14}");
        foreach (var (name, (opens, commands, commits)) in results.OrderBy(r => r.Key, StringComparer.Ordinal))
        {
            _output.WriteLine($"{name,-36} {opens,6} {commands,9} {commits,14}");
        }

        // Opens on the request path. /token and /userinfo are the high-volume endpoints: at most one open each.
        var budget = new Dictionary<string, int>
        {
            ["POST /token client_credentials"] = 0,
            ["POST /token authorization_code"] = 1,
            ["POST /token refresh_token"] = 1,
            ["GET /userinfo"] = 1,
            ["GET /authorize (signed in)"] = 2,
            ["POST /revoke"] = 3,
            ["POST /session/v1/login"] = 5,
        };
        Assert.All(budget, b => Assert.True(results[b.Key].Opens <= b.Value, $"{b.Key}: {results[b.Key].Opens} opens, budget {b.Value}"));
    }
}
