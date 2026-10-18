using System.Net;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Common;

namespace Heimdall.UnitTests.Domain;

public class AuditEventTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private static AuditEvent Record(string type = AuditEventTypes.CodeReuseDetected, Dictionary<string, string>? data = null) =>
        AuditEvent.Record(
            Guid.CreateVersion7(),
            Guid.CreateVersion7(),
            type,
            "corr-123",
            Now,
            IPAddress.Parse("203.0.113.7"),
            familyId: Guid.CreateVersion7(),
            data: data);

    [Fact]
    public void Event_keeps_its_values()
    {
        var evt = Record(data: new() { ["reason"] = "already_redeemed" });

        Assert.Equal(AuditEventTypes.CodeReuseDetected, evt.Type);
        Assert.Equal("corr-123", evt.CorrelationId);
        Assert.Equal("already_redeemed", evt.Data["reason"]);
    }

    [Fact]
    public void Data_is_copied_so_the_caller_cannot_change_it_later()
    {
        var data = new Dictionary<string, string> { ["reason"] = "first" };
        var evt = Record(data: data);

        data["reason"] = "changed";

        Assert.Equal("first", evt.Data["reason"]);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("client_secret")]
    [InlineData("refresh_token")]
    [InlineData("code_verifier")]
    [InlineData("code")]
    [InlineData("client_assertion")]
    [InlineData("Cookie")]
    public void Data_key_that_suggests_a_secret_is_rejected(string key)
    {
        Assert.Throws<DomainException>(() => Record(data: new() { [key] = "value" }));
    }

    [Theory]
    [InlineData("CodeRedeemed")]
    [InlineData("code redeemed")]
    [InlineData("code")]
    [InlineData("code.")]
    public void Type_must_have_the_area_action_form(string type)
    {
        Assert.Throws<DomainException>(() => Record(type));
    }

    [Fact]
    public void Every_defined_type_has_a_valid_form()
    {
        var types = typeof(AuditEventTypes).GetFields()
            .Where(f => f.IsLiteral)
            .Select(f => (string)f.GetRawConstantValue()!);

        foreach (var type in types)
        {
            Assert.Equal(type, Record(type).Type);
        }
    }
}
