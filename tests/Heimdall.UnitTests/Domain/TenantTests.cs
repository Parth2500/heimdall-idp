using Heimdall.Domain.Common;
using Heimdall.Domain.Tenants;

namespace Heimdall.UnitTests.Domain;

public class TenantTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Host_is_stored_in_lowercase()
    {
        var tenant = Tenant.Create(Guid.CreateVersion7(), " Acme.Example.COM ", "Acme", TenantSettings.Default, Now);

        Assert.Equal("acme.example.com", tenant.Host);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("*.example.com")]
    [InlineData("acme_corp.example.com")]
    [InlineData("-acme.example.com")]
    [InlineData("acme..example.com")]
    [InlineData("acme.example.com/path")]
    [InlineData("acme.example.com:8443")]
    public void Invalid_host_is_rejected(string host)
    {
        Assert.Throws<DomainException>(() =>
            Tenant.Create(Guid.CreateVersion7(), host, "Acme", TenantSettings.Default, Now));
    }

    [Fact]
    public void Empty_id_is_rejected()
    {
        Assert.Throws<DomainException>(() =>
            Tenant.Create(Guid.Empty, "acme.example.com", "Acme", TenantSettings.Default, Now));
    }

    [Fact]
    public void New_tenant_is_active()
    {
        var tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);

        Assert.Equal(TenantStatus.Active, tenant.Status);
    }

    [Fact]
    public void Session_idle_longer_than_absolute_is_rejected()
    {
        Assert.Throws<DomainException>(() => new TenantSettings(
            sessionIdle: TimeSpan.FromHours(13),
            sessionAbsolute: TimeSpan.FromHours(12),
            accessToken: TimeSpan.FromMinutes(5),
            refreshIdle: TimeSpan.FromDays(7),
            refreshAbsolute: TimeSpan.FromDays(30)));
    }

    [Fact]
    public void Refresh_idle_longer_than_absolute_is_rejected()
    {
        Assert.Throws<DomainException>(() => new TenantSettings(
            sessionIdle: TimeSpan.FromMinutes(30),
            sessionAbsolute: TimeSpan.FromHours(12),
            accessToken: TimeSpan.FromMinutes(5),
            refreshIdle: TimeSpan.FromDays(31),
            refreshAbsolute: TimeSpan.FromDays(30)));
    }

    [Fact]
    public void Zero_lifetime_is_rejected()
    {
        Assert.Throws<DomainException>(() => new TenantSettings(
            sessionIdle: TimeSpan.FromMinutes(30),
            sessionAbsolute: TimeSpan.FromHours(12),
            accessToken: TimeSpan.Zero,
            refreshIdle: TimeSpan.FromDays(7),
            refreshAbsolute: TimeSpan.FromDays(30)));
    }

    [Fact]
    public void Default_settings_match_the_threat_model()
    {
        var defaults = TenantSettings.Default;

        Assert.Equal(TimeSpan.FromMinutes(30), defaults.SessionIdle);
        Assert.Equal(TimeSpan.FromHours(12), defaults.SessionAbsolute);
        Assert.Equal(TimeSpan.FromMinutes(5), defaults.AccessToken);
        Assert.Equal(TimeSpan.FromDays(7), defaults.RefreshIdle);
        Assert.Equal(TimeSpan.FromDays(30), defaults.RefreshAbsolute);
    }
}
