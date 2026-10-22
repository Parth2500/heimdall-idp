using System.Text;
using Heimdall.Api.Endpoints;
using Heimdall.Application.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Heimdall.UnitTests.Api;

public class OAuthFormReaderTests
{
    private const string FormType = "application/x-www-form-urlencoded";
    private const int MaxBodyBytes = 16 * 1024;

    private static DefaultHttpContext Request(
        string body,
        string? contentType = FormType,
        string? authorization = null,
        string? query = null,
        long? contentLength = null)
    {
        var context = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes(body);
        context.Request.Method = "POST";
        context.Request.ContentType = contentType;
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = contentLength ?? bytes.Length;
        if (authorization is not null)
        {
            context.Request.Headers.Authorization = authorization;
        }

        if (query is not null)
        {
            context.Request.QueryString = new QueryString(query);
        }

        return context;
    }

    private static string Basic(string credentials) => "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));

    private static Task<OAuthForm> Read(DefaultHttpContext context) => OAuthFormReader.ReadAsync(context);

    private static void AssertFails(OAuthForm form, string code, string reason)
    {
        Assert.NotNull(form.Error);
        Assert.Equal(code, form.Error.Code);
        Assert.Equal(reason, form.Error.AuditDetail);
        Assert.Null(form.Form);
        Assert.Null(form.ClientId);
        Assert.Null(form.ClientSecret);
    }

    [Fact]
    public async Task Public_client_sends_its_id_in_the_body()
    {
        var form = await Read(Request("grant_type=refresh_token&client_id=spa&refresh_token=abc"));

        Assert.Null(form.Error);
        Assert.Equal("spa", form.ClientId);
        Assert.Null(form.ClientSecret);
        Assert.Equal("refresh_token", form.Form!["grant_type"]);
        Assert.Equal("abc", form.Form["refresh_token"]);
    }

    [Fact]
    public async Task Confidential_client_sends_Basic_credentials()
    {
        var form = await Read(Request("grant_type=client_credentials", authorization: Basic("billing:s3cret")));

        Assert.Null(form.Error);
        Assert.Equal("billing", form.ClientId);
        Assert.Equal("s3cret", form.ClientSecret);
    }

    [Fact]
    public async Task Basic_credentials_are_form_decoded()
    {
        // RFC 6749, section 2.3.1: encode each value, then join with a colon. "+" is a space and %3A is a colon.
        var form = await Read(Request("grant_type=client_credentials", authorization: Basic("my+client:p%3Ass+w%25rd")));

        Assert.Equal("my client", form.ClientId);
        Assert.Equal("p:ss w%rd", form.ClientSecret);
    }

    [Fact]
    public async Task Secret_may_contain_a_colon_after_the_first()
    {
        var form = await Read(Request("grant_type=client_credentials", authorization: Basic("billing:a:b")));

        Assert.Equal("billing", form.ClientId);
        Assert.Equal("a:b", form.ClientSecret);
    }

    [Fact]
    public async Task Empty_secret_is_an_empty_string()
    {
        var form = await Read(Request("grant_type=client_credentials", authorization: Basic("billing:")));

        Assert.Equal("billing", form.ClientId);
        Assert.Equal(string.Empty, form.ClientSecret);
    }

    [Theory]
    [InlineData("basic ")]
    [InlineData("BASIC ")]
    public async Task Basic_scheme_is_case_insensitive(string scheme)
    {
        var header = scheme + Convert.ToBase64String(Encoding.UTF8.GetBytes("billing:s3cret"));

        Assert.Equal("billing", (await Read(Request("grant_type=client_credentials", authorization: header))).ClientId);
    }

    [Fact]
    public async Task Same_client_id_in_the_body_and_the_header_is_accepted()
    {
        var form = await Read(Request("client_id=billing", authorization: Basic("billing:s3cret")));

        Assert.Null(form.Error);
        Assert.Equal("billing", form.ClientId);
    }

    [Fact]
    public async Task Different_client_id_in_the_body_and_the_header_is_refused()
    {
        AssertFails(
            await Read(Request("client_id=other", authorization: Basic("billing:s3cret"))),
            OAuthError.InvalidRequestCode,
            "client_id in body differs from the header");
    }

    [Fact]
    public async Task Empty_client_id_in_the_body_is_no_client_id()
    {
        Assert.Null((await Read(Request("grant_type=refresh_token&client_id="))).ClientId);
    }

    [Fact]
    public async Task Empty_client_id_in_the_body_does_not_conflict_with_the_header()
    {
        Assert.Equal("billing", (await Read(Request("client_id=", authorization: Basic("billing:s3cret")))).ClientId);
    }

    [Fact]
    public async Task Query_string_is_refused()
    {
        // Proxies and access logs keep query strings, so credentials must never travel there.
        AssertFails(
            await Read(Request("grant_type=client_credentials", query: "?client_secret=x")),
            OAuthError.InvalidRequestCode,
            "query string present");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("application/json")]
    [InlineData("multipart/form-data; boundary=x")]
    [InlineData("text/plain")]
    [InlineData("not a media type")]
    public async Task Content_type_other_than_form_is_refused(string? contentType)
    {
        AssertFails(
            await Read(Request("grant_type=client_credentials", contentType)),
            OAuthError.InvalidRequestCode,
            "content type is not form-urlencoded");
    }

    [Theory]
    [InlineData("application/x-www-form-urlencoded; charset=utf-8")]
    [InlineData("Application/X-WWW-Form-Urlencoded")]
    public async Task Form_content_type_with_parameters_or_other_case_is_accepted(string contentType)
    {
        Assert.Null((await Read(Request("grant_type=client_credentials", contentType))).Error);
    }

    [Fact]
    public async Task Declared_body_over_the_limit_is_refused_before_reading()
    {
        var context = Request("grant_type=client_credentials", contentLength: MaxBodyBytes + 1);

        AssertFails(await Read(context), OAuthError.InvalidRequestCode, "body too large");
        Assert.Equal(0, context.Request.Body.Position);
    }

    [Fact]
    public async Task Body_of_exactly_the_limit_is_read()
    {
        // Five values of 3,000 characters and one filler value make exactly 16 KiB.
        var values = string.Join("&", Enumerable.Range(0, 5).Select(i => $"v{i}=" + new string('x', 3000)));
        var body = values + "&pad=";
        body += new string('y', MaxBodyBytes - body.Length);

        Assert.Equal(MaxBodyBytes, Encoding.UTF8.GetByteCount(body));
        Assert.Null((await Read(Request(body))).Error);
    }

    [Fact]
    public async Task Body_size_limit_is_set_for_the_server()
    {
        var context = Request("grant_type=client_credentials");
        var sizeFeature = new SizeFeature(isReadOnly: false);
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(sizeFeature);

        await Read(context);

        Assert.Equal(MaxBodyBytes, sizeFeature.MaxRequestBodySize);
    }

    [Fact]
    public async Task Read_only_body_size_limit_is_left_as_it_is()
    {
        var context = Request("grant_type=client_credentials");
        var sizeFeature = new SizeFeature(isReadOnly: true);
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(sizeFeature);

        await Read(context);

        Assert.Null(sizeFeature.MaxRequestBodySize);
    }

    [Fact]
    public async Task More_than_16_values_are_refused()
    {
        var body = string.Join("&", Enumerable.Range(0, 17).Select(i => $"p{i}=v"));

        AssertFails(await Read(Request(body)), OAuthError.InvalidRequestCode, "form over limits");
    }

    [Fact]
    public async Task Sixteen_values_are_accepted()
    {
        var body = string.Join("&", Enumerable.Range(0, 16).Select(i => $"p{i}=v"));

        Assert.Null((await Read(Request(body))).Error);
    }

    [Fact]
    public async Task Value_over_4096_characters_is_refused()
    {
        AssertFails(await Read(Request("token=" + new string('x', 4097))), OAuthError.InvalidRequestCode, "form over limits");
    }

    [Fact]
    public async Task Value_of_4096_characters_is_accepted()
    {
        Assert.Null((await Read(Request("token=" + new string('x', 4096)))).Error);
    }

    [Fact]
    public async Task Key_over_64_characters_is_refused()
    {
        AssertFails(await Read(Request(new string('k', 65) + "=v")), OAuthError.InvalidRequestCode, "form over limits");
    }

    [Fact]
    public async Task Body_that_the_server_refuses_is_over_limits()
    {
        var context = Request("grant_type=client_credentials");
        context.Request.Body = new RefusingStream();

        AssertFails(await Read(context), OAuthError.InvalidRequestCode, "body over limits");
    }

    [Theory]
    [InlineData("grant_type=client_credentials&grant_type=refresh_token")]
    [InlineData("scope=a&scope=a")]
    [InlineData("client_id=spa&client_id=spa")]
    public async Task Repeated_parameter_is_refused(string body)
    {
        // RFC 6749, section 3.2 and RFC 7009, section 2.1: a repeated parameter makes the request ambiguous.
        AssertFails(await Read(Request(body)), OAuthError.InvalidRequestCode, "repeated parameter");
    }

    [Fact]
    public async Task Secret_in_the_body_is_refused()
    {
        // D10: client_secret_basic is the only method for a confidential client.
        AssertFails(
            await Read(Request("client_id=billing&client_secret=s3cret")),
            OAuthError.InvalidRequestCode,
            "client_secret_post not supported");
    }

    [Fact]
    public async Task Empty_secret_in_the_body_is_refused_too()
    {
        AssertFails(await Read(Request("client_id=billing&client_secret=")), OAuthError.InvalidRequestCode, "client_secret_post not supported");
    }

    [Fact]
    public async Task Repeated_authorization_header_is_refused()
    {
        var context = Request("grant_type=client_credentials");
        context.Request.Headers.Authorization = new(new[] { Basic("a:b"), Basic("c:d") });

        AssertFails(await Read(context), OAuthError.InvalidRequestCode, "repeated Authorization header");
    }

    [Theory]
    [InlineData("Bearer abc")]
    [InlineData("Basic")]
    [InlineData("Digest username=\"a\"")]
    public async Task Scheme_other_than_Basic_is_invalid_client(string header)
    {
        AssertFails(
            await Read(Request("grant_type=client_credentials", authorization: header)),
            OAuthError.InvalidClientCode,
            "authorization scheme is not Basic");
    }

    [Theory]
    [InlineData("Basic not base64!")]
    [InlineData("Basic YWJj=")]
    public async Task Basic_value_that_is_not_base64_is_invalid_client(string header)
    {
        AssertFails(
            await Read(Request("grant_type=client_credentials", authorization: header)),
            OAuthError.InvalidClientCode,
            "Basic credentials are not base64");
    }

    [Fact]
    public async Task Basic_value_that_is_not_UTF8_is_invalid_client()
    {
        var header = "Basic " + Convert.ToBase64String([0x62, 0x3A, 0xFF, 0xFE]);

        AssertFails(
            await Read(Request("grant_type=client_credentials", authorization: header)),
            OAuthError.InvalidClientCode,
            "Basic credentials are not UTF-8");
    }

    [Theory]
    [InlineData("billing")] // no colon
    [InlineData(":s3cret")] // empty client ID
    [InlineData("")]
    public async Task Basic_value_without_a_client_id_is_invalid_client(string credentials)
    {
        AssertFails(
            await Read(Request("grant_type=client_credentials", authorization: Basic(credentials))),
            OAuthError.InvalidClientCode,
            "Basic credentials have no client ID");
    }

    [Fact]
    public async Task Basic_value_with_surrounding_space_is_trimmed()
    {
        var header = "Basic  " + Convert.ToBase64String(Encoding.UTF8.GetBytes("billing:s3cret")) + " ";

        Assert.Equal("billing", (await Read(Request("grant_type=client_credentials", authorization: header))).ClientId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Empty_value_is_null(string? value)
    {
        Assert.Null(OAuthFormReader.NullIfEmpty(value));
    }

    [Fact]
    public void Value_is_kept()
    {
        Assert.Equal("spa", OAuthFormReader.NullIfEmpty("spa"));
    }

    private sealed class SizeFeature(bool isReadOnly) : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly { get; } = isReadOnly;

        public long? MaxRequestBodySize { get; set; }
    }

    /// <summary>A body that the server stops, as Kestrel does when the body passes its size limit.</summary>
    private sealed class RefusingStream : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            throw new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            throw new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge);
    }
}
