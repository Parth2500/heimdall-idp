using Heimdall.Api.Endpoints;
using Heimdall.Application.Logout;
using Microsoft.AspNetCore.DataProtection;

namespace Heimdall.UnitTests.Api;

/// <summary>U17: the confirm page carries one sealed value. Only an unchanged value of the same tenant opens.</summary>
public class LogoutRequestProtectorTests
{
    private static readonly Guid Tenant = Guid.CreateVersion7();
    private static readonly LogoutTarget Target = new(Guid.CreateVersion7(), "https://app.example.com/bye", "xyz");

    private readonly LogoutRequestProtector _protector = new(new EphemeralDataProtectionProvider());

    [Fact]
    public void Sealed_target_opens_unchanged() =>
        Assert.Equal(Target, _protector.Unprotect(Tenant, _protector.Protect(Tenant, Target)));

    [Fact]
    public void Target_without_state_opens_unchanged()
    {
        var target = Target with { State = null };

        Assert.Equal(target, _protector.Unprotect(Tenant, _protector.Protect(Tenant, target)));
    }

    [Fact]
    public void Sealed_value_shows_no_uri()
    {
        var value = _protector.Protect(Tenant, Target);

        Assert.DoesNotContain("app.example.com", value, StringComparison.Ordinal);
        Assert.DoesNotContain("xyz", value, StringComparison.Ordinal);
    }

    [Fact]
    public void Value_of_another_tenant_does_not_open() =>
        Assert.Null(_protector.Unprotect(Guid.CreateVersion7(), _protector.Protect(Tenant, Target)));

    [Fact]
    public void Value_of_another_key_ring_does_not_open() =>
        Assert.Null(new LogoutRequestProtector(new EphemeralDataProtectionProvider()).Unprotect(Tenant, _protector.Protect(Tenant, Target)));

    [Fact]
    public void Changed_value_does_not_open()
    {
        var value = _protector.Protect(Tenant, Target);
        var changed = value[..^4] + (value[^4] == 'A' ? "BBBB" : "AAAA");

        Assert.Null(_protector.Unprotect(Tenant, changed));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-sealed")]
    public void Missing_or_plain_value_does_not_open(string? value) =>
        Assert.Null(_protector.Unprotect(Tenant, value));

    [Fact]
    public void Oversized_value_is_refused_before_it_is_read() =>
        Assert.Null(_protector.Unprotect(Tenant, new string('A', 4097)));
}
