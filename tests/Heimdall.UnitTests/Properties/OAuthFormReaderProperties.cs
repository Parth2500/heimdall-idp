using System.Net;
using System.Text;
using CsCheck;
using Heimdall.Api.Endpoints;
using Microsoft.AspNetCore.Http;

namespace Heimdall.UnitTests.Properties;

public class OAuthFormReaderProperties
{
    private static readonly Gen<string?> ContentType = Gen.OneOfConst<string?>(
        null,
        "",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=utf-8",
        "application/x-www-form-urlencoded; charset=utf-16",
        "application/x-www-form-urlencoded; charset=utf-7",
        "application/x-www-form-urlencoded; charset=no-such-charset",
        "application/x-www-form-urlencoded; charset=",
        "APPLICATION/X-WWW-FORM-URLENCODED;;;",
        "application/json",
        "multipart/form-data; boundary=x",
        "text/plain; charset=utf-8");

    /// <summary>Basic values of every shape: random text, random base64, and base64 of random bytes.</summary>
    private static readonly Gen<string?> Authorization = Gen.Frequency(
        (1, Gen.Const<string?>((string?)null)),
        (1, Generators.AnyString.Select(s => (string?)s)),
        (1, Generators.AnyString.Select(s => (string?)("Basic " + s))),
        (2, Gen.Byte.Array[0, 40].Select(b => (string?)("Basic " + Convert.ToBase64String(b)))),
        (2, Generators.UnicodeText.Select(s => (string?)("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(s))))));

    /// <summary>Bodies of every shape: random bytes, and random text with the separators that a form uses.</summary>
    private static readonly Gen<byte[]> Body = Gen.Frequency(
        (1, Gen.Byte.Array[0, 300]),
        (2, Gen.String[Gen.Frequency((6, Generators.AnyChar), (2, Gen.Char["=&+%"])), 0, 300].Select(Encoding.UTF8.GetBytes)));

    private static DefaultHttpContext Request(byte[] body, string? contentType, string? authorization, string? query)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.ContentType = contentType;
        context.Request.Body = new MemoryStream(body);
        context.Request.ContentLength = body.Length;
        if (authorization is not null)
        {
            context.Request.Headers.Authorization = authorization;
        }

        if (query is not null)
        {
            context.Request.QueryString = new QueryString("?" + query);
        }

        return context;
    }

    /// <summary>application/x-www-form-urlencoded, as RFC 6749 section 2.3.1 and appendix B require.</summary>
    private static string FormEncode(string value) => WebUtility.UrlEncode(value);

    [Fact]
    public async Task Any_request_gives_a_form_or_an_error_and_never_an_exception()
    {
        var query = Gen.Frequency((4, Gen.Const<string?>((string?)null)), (1, Gen.String[Gen.Char['a', 'z'], 1, 10].Select(s => (string?)s)));

        await Gen.Select(Body, ContentType, Authorization, query).SampleAsync(async (body, contentType, authorization, q) =>
        {
            var form = await OAuthFormReader.ReadAsync(Request(body, contentType, authorization, q));

            if (form.Error is not null)
            {
                Assert.Null(form.Form);
                Assert.Null(form.ClientId);
                Assert.Null(form.ClientSecret);
            }
            else
            {
                Assert.NotNull(form.Form);
                Assert.NotEqual(string.Empty, form.ClientId);
                Assert.False(form.Form.ContainsKey("client_secret"));
                Assert.All(form.Form, p => Assert.Single(p.Value));
                Assert.Null(q);
            }
        }, iter: 5_000);
    }

    [Fact]
    public async Task Any_client_id_and_secret_survive_Basic_encoding()
    {
        var id = Generators.UnicodeText.Where(s => s.Length > 0);

        await Gen.Select(id, Generators.UnicodeText).SampleAsync(async (clientId, secret) =>
        {
            var credentials = FormEncode(clientId) + ":" + FormEncode(secret);
            var header = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));

            var form = await OAuthFormReader.ReadAsync(Request("grant_type=client_credentials"u8.ToArray(), "application/x-www-form-urlencoded", header, null));

            Assert.Null(form.Error);
            Assert.Equal(clientId, form.ClientId);
            Assert.Equal(secret, form.ClientSecret);
        }, iter: 3_000);
    }

    [Fact]
    public async Task Any_form_parameters_within_the_limits_come_back_unchanged()
    {
        // The limits count the encoded text on the wire: 64 characters for a key, 4,096 for a value. ASP.NET Core refuses
        // a NUL character, and NUL_in_a_key_or_value_is_refused covers that case.
        var text = Generators.UnicodeText.Where(s => !s.Contains('\0', StringComparison.Ordinal));
        var key = text.Where(k => k.Length > 0 && FormEncode(k).Length <= 64 && k is not "client_secret");
        // ASP.NET Core compares form names without case, so "J" and "j" are one repeated name.
        // Same_name_in_another_case_is_a_repeated_parameter covers that case.
        var parameters = Gen.Dictionary(key, text)[0, 16]
            .Where(d => d.Keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() == d.Count);

        await parameters.SampleAsync(async values =>
        {
            var body = string.Join("&", values.Select(p => FormEncode(p.Key) + "=" + FormEncode(p.Value)));

            var form = await OAuthFormReader.ReadAsync(Request(Encoding.UTF8.GetBytes(body), "application/x-www-form-urlencoded", null, null));

            Assert.Null(form.Error);
            Assert.Equal(values.Count, form.Form!.Count);
            Assert.All(values, p => Assert.Equal(p.Value, form.Form[p.Key].ToString()));
        }, iter: 2_000);
    }
}
