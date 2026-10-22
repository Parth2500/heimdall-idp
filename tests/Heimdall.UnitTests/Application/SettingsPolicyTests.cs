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

        var errors = _policy.Validate(settings);

        Assert.Equal(
            [
                "Session idle timeout",
                "Session absolute lifetime",
                "Access token lifetime",
                "Refresh idle timeout",
                "Refresh absolute lifetime",
            ],
            errors.Select(e => e[..e.IndexOf(" must", StringComparison.Ordinal)]));
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

        Assert.StartsWith("Access token lifetime", Assert.Single(_policy.Validate(overrides)), StringComparison.Ordinal);
    }

    [Fact]
    public void Client_refresh_overrides_outside_the_limits_are_rejected()
    {
        // Each refresh value is inside the Domain rule (idle not longer than absolute) but outside the platform limits.
        var overrides = new ClientTokenOverrides(null, TimeSpan.FromMinutes(10), TimeSpan.FromDays(365));

        var errors = _policy.Validate(overrides);

        Assert.Equal(2, errors.Count);
        Assert.StartsWith("Refresh idle timeout", errors[0], StringComparison.Ordinal);
        Assert.StartsWith("Refresh absolute lifetime", errors[1], StringComparison.Ordinal);
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

        Assert.StartsWith("SessionIdle: the minimum must be greater than zero", Assert.Single(limits.Validate()), StringComparison.Ordinal);
    }

    [Fact]
    public void Limit_contains_both_ends()
    {
        var limit = new DurationLimit(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(60));

        Assert.True(limit.Contains(TimeSpan.FromMinutes(1)));
        Assert.True(limit.Contains(TimeSpan.FromMinutes(60)));
        Assert.False(limit.Contains(TimeSpan.FromMinutes(1) - TimeSpan.FromTicks(1)));
        Assert.False(limit.Contains(TimeSpan.FromMinutes(60) + TimeSpan.FromTicks(1)));
        Assert.Equal("00:01:00 to 01:00:00", limit.ToString());
    }

    [Fact]
    public void Limit_with_the_same_minimum_and_maximum_is_valid()
    {
        var limits = new PlatformLimits { AccessToken = new DurationLimit(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5)) };

        Assert.Empty(limits.Validate());
    }

    [Theory]
    [InlineData(nameof(PlatformLimits.SessionIdle))]
    [InlineData(nameof(PlatformLimits.SessionAbsolute))]
    [InlineData(nameof(PlatformLimits.AccessToken))]
    [InlineData(nameof(PlatformLimits.RefreshIdle))]
    [InlineData(nameof(PlatformLimits.RefreshAbsolute))]
    public void Every_platform_limit_is_checked(string name)
    {
        var limits = new PlatformLimits();
        var inverted = new DurationLimit(TimeSpan.FromHours(2), TimeSpan.FromHours(1));
        typeof(PlatformLimits).GetProperty(name)!.SetValue(limits, inverted);

        Assert.Equal(
            $"{name}: the minimum must not be greater than the maximum.",
            Assert.Single(limits.Validate()));
    }

    [Fact]
    public void Missing_platform_limit_is_reported()
    {
        // A configuration section can bind null to a limit.
        var limits = new PlatformLimits { RefreshIdle = null! };

        Assert.Equal("RefreshIdle: the limit is missing.", Assert.Single(limits.Validate()));
    }
}
