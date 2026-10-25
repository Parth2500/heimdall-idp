using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// The Angular account pages under <c>/account/</c> on each tenant origin (U2). Heimdall serves <c>index.html</c> itself, with
/// a new nonce and a strict policy on each response (U3). The hashed bundle files are plain static files.
/// </summary>
internal static partial class AccountPages
{
    public const string Prefix = "/account";

    /// <summary>The placeholder in the built <c>index.html</c>. The build copies it into every script and style tag.</summary>
    public const string NoncePlaceholder = "__HEIMDALL_CSP_NONCE__";

    /// <summary>The routes of the Angular application. Any other path under the prefix is a static file or 404.</summary>
    public static readonly IReadOnlyList<string> Pages = ["login", "consent", "error", "logout", "signed-out"];

    // U3. No 'unsafe-inline': Angular puts the nonce on the styles that it adds at run time.
    private const string PolicyTemplate =
        "default-src 'none'; " +
        "script-src 'self' 'nonce-{nonce}'; " +
        "style-src 'self' 'nonce-{nonce}'; " +
        "img-src 'self'; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "form-action 'self'; " +
        "base-uri 'none'; " +
        "frame-ancestors 'none'; " +
        "require-trusted-types-for 'script'; " +
        "trusted-types angular angular#bundler";

    public static void Map(WebApplication app)
    {
        var options = app.Services.GetRequiredService<IOptions<UiOptions>>().Value;
        var directory = Path.Combine(app.Environment.ContentRootPath, options.AccountDirectory);
        app.Services.GetRequiredService<AccountIndex>().Directory = directory;

        foreach (var page in Pages)
        {
            app.MapGet($"{Prefix}/{page}", ServePageAsync);
        }

        if (!Directory.Exists(directory))
        {
            LogNotBuilt(app.Logger, directory);
            return;
        }

        app.UseStaticFiles(new StaticFileOptions
        {
            RequestPath = Prefix,
            FileProvider = new PhysicalFileProvider(directory),
            ContentTypeProvider = BundleTypes(),
            OnPrepareResponse = context =>
            {
                // The build puts a content hash in each bundle name, so a cached copy can never be stale.
                var headers = context.Context.Response.Headers;
                headers.CacheControl = IsHashed(context.File.Name)
                    ? "public, max-age=31536000, immutable"
                    : "no-cache";
            },
        });
    }

    private static async Task ServePageAsync(HttpContext context, AccountIndex index)
    {
        var html = await index.ReadAsync(context.RequestAborted).ConfigureAwait(false);
        if (html is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var nonce = NewNonce();
        var response = context.Response;
        response.Headers.ContentSecurityPolicy = PolicyTemplate.Replace("{nonce}", nonce, StringComparison.Ordinal);

        // Each copy has its own nonce. A cached copy would reuse a nonce that a page already exposed.
        response.Headers.CacheControl = "no-store";
        response.ContentType = "text/html; charset=utf-8";
        await response.WriteAsync(html.Replace(NoncePlaceholder, nonce, StringComparison.Ordinal), context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>128 random bits, base64url (CSP Level 3 allows the base64url alphabet for a nonce).</summary>
    internal static string NewNonce() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

    /// <summary>
    /// Only bundle types. <c>index.html</c> has no type here, so the static file middleware never serves it without its
    /// nonce and policy.
    /// </summary>
    private static FileExtensionContentTypeProvider BundleTypes()
    {
        var provider = new FileExtensionContentTypeProvider();
        provider.Mappings.Clear();
        provider.Mappings[".js"] = "text/javascript";
        provider.Mappings[".css"] = "text/css";
        provider.Mappings[".ico"] = "image/x-icon";
        provider.Mappings[".svg"] = "image/svg+xml";
        provider.Mappings[".png"] = "image/png";
        provider.Mappings[".woff2"] = "font/woff2";
        return provider;
    }

    /// <summary>
    /// Angular names hashed files <c>name-HASH.ext</c>, with an 8-character upper-case hash. Fonts go to
    /// <c>media/</c> with the same pattern.
    /// </summary>
    private static bool IsHashed(string fileName) => HashedName().IsMatch(fileName);

    [System.Text.RegularExpressions.GeneratedRegex(@"-[A-Z0-9]{8}\.(js|css|woff2)$")]
    private static partial System.Text.RegularExpressions.Regex HashedName();

    [LoggerMessage(Level = LogLevel.Warning, Message = "The account pages are not built at {Directory}. Run the ui build. The pages answer 404.")]
    private static partial void LogNotBuilt(ILogger logger, string directory);
}

/// <summary>
/// The built <c>index.html</c>, read once and read again when the file changes, so <c>ng build --watch</c> works in
/// development. The file is small, and the page volume is low (one load for each sign-in).
/// </summary>
internal sealed class AccountIndex
{
    private volatile CachedPage? _cached;

    public string Directory { get; set; } = string.Empty;

    public async Task<string?> ReadAsync(CancellationToken cancellationToken)
    {
        var file = new FileInfo(Path.Combine(Directory, "index.html"));
        if (!file.Exists)
        {
            return null;
        }

        if (_cached is { } hit && hit.WrittenAt == file.LastWriteTimeUtc)
        {
            return hit.Html;
        }

        // Two requests can read the file at the same time after a change. Both get the same content.
        var html = await File.ReadAllTextAsync(file.FullName, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        _cached = new CachedPage(file.LastWriteTimeUtc, html);
        return html;
    }
}

internal sealed record CachedPage(DateTime WrittenAt, string Html);
