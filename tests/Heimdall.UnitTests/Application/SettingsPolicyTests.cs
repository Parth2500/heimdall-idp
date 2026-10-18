using Heimdall.Application.Settings;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;

namespace Heimdall.UnitTests.Application;

public class SettingsPolicyTests
{
    private readonly SettingsPolicy _policy = new(new PlatformLimits());

    [Fact]
    public void Default_tenant_settings_are_inside_the_default_limits()
    {
        Assert.Empty(_policy.Validate(TenantSettings.Default));
    }

    [Fact]
    public void Tenant_access_token_longer_than_the_maximum_is_rejected()
    {
        var settings = new TenantSettings(
            sessionIdle: TimeSpan.FromMinutes(30),
            sessionAbsolute: TimeSpan.FromHours(12),
            accessToken: TimeSpan.FromHours(2),
            refreshIdle: TimeSpan.FromDays(7),
            refreshAbsolute: TimeSpan.FromDays(30));

        var errors = _policy.Validate(settings);

        Assert.Single(errors);
        Assert.Contains("Access token lifetime", errors[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Every_out_of_range_tenant_value_is_reported()
    {
        var settings = new TenantSettings(
            sessionIdle: TimeSpan.FromMinutes(1),
            sessionAbsolute: TimeSpan.FromDays(60),
            accessToken: TimeSpan.FromSeconds(10),
            refreshIdle: TimeSpan.FromMinutes(10),
            refreshAbsolute: TimeSpan.FromDays(365));

        Assert.Equal(5, _policy.Validate(settings).Count);
    }

    [Fact]
    public void Client_overrides_that_are_null_are_not_checked()
    {
        Assert.Empty(_policy.Validate(ClientTokenOverrides.None));
    }

    [Fact]
    public void Client_override_outside_the_limits_is_rejected()
    {
        var overrides = new ClientTokenOverrides(TimeSpan.FromDays(1), null, null);

        Assert.Single(_policy.Validate(overrides));
    }

    [Fact]
    public void Client_override_inside_the_limits_is_accepted()
    {
        var overrides = new ClientTokenOverrides(TimeSpan.FromMinutes(15), TimeSpan.FromDays(1), TimeSpan.FromDays(14));

        Assert.Empty(_policy.Validate(overrides));
    }

    [Fact]
    public void Invalid_platform_limits_stop_the_policy_from_starting()
    {
        var limits = new PlatformLimits
        {
            AccessToken = new DurationLimit(TimeSpan.FromHours(2), TimeSpan.FromMinutes(5)),
        };

        Assert.Throws<ArgumentException>(() => new SettingsPolicy(limits));
    }

    [Fact]
    public void Zero_minimum_is_not_a_valid_limit()
    {
        var limits = new PlatformLimits { SessionIdle = new DurationLimit(TimeSpan.Zero, TimeSpan.FromHours(1)) };

        Assert.NotEmpty(limits.Validate());
    }
}
