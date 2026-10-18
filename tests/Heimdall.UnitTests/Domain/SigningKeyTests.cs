using Heimdall.Domain.Common;
using Heimdall.Domain.Keys;

namespace Heimdall.UnitTests.Domain;

public class SigningKeyTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromHours(1);
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(1);
    private static readonly Guid TenantId = Guid.CreateVersion7();

    private static SigningKey NewKey(string kid, DateTimeOffset createdAt, Guid? tenantId = null) =>
        SigningKey.Create(
            Guid.CreateVersion7(),
            tenantId ?? TenantId,
            kid,
            "{\"kty\":\"RSA\"}",
            $"file:.local/signing-keys.json#{kid}",
            CacheLifetime,
            createdAt);

    [Fact]
    public void New_key_is_published_but_cannot_sign()
    {
        var key = NewKey("k1", Now);

        Assert.Equal(SigningKeyStatus.Pending, key.Status);
        Assert.True(key.IsPublished(Now));
        Assert.False(key.CanSign);
    }

    [Fact]
    public void First_key_cannot_sign_before_the_cache_lifetime()
    {
        var key = NewKey("k1", Now);

        Assert.Throws<DomainException>(() => SigningKeyRotation.ActivateFirst(key, Now.AddMinutes(59)));

        SigningKeyRotation.ActivateFirst(key, Now.AddHours(1));
        Assert.True(key.CanSign);
    }

    [Fact]
    public void Rotation_activates_the_next_key_and_keeps_the_old_one_published()
    {
        var current = NewKey("k1", Now);
        SigningKeyRotation.ActivateFirst(current, Now.AddHours(1));
        var next = NewKey("k2", Now.AddDays(1));
        var rotateAt = Now.AddDays(1).AddHours(1);

        SigningKeyRotation.Rotate(current, next, TokenLifetime, Skew, rotateAt);

        Assert.True(next.CanSign);
        Assert.False(current.CanSign);
        Assert.Equal(rotateAt + TokenLifetime + Skew, current.RemoveAfter);
        Assert.True(current.IsPublished(rotateAt.AddMinutes(5)));
        Assert.False(current.IsPublished(rotateAt.AddMinutes(6)));
    }

    [Fact]
    public void Rotation_too_early_leaves_the_current_key_active()
    {
        var current = NewKey("k1", Now);
        SigningKeyRotation.ActivateFirst(current, Now.AddHours(1));
        var next = NewKey("k2", Now.AddDays(1));

        Assert.Throws<DomainException>(() =>
            SigningKeyRotation.Rotate(current, next, TokenLifetime, Skew, Now.AddDays(1).AddMinutes(10)));

        Assert.True(current.CanSign);
        Assert.Equal(SigningKeyStatus.Pending, next.Status);
    }

    [Fact]
    public void Rotation_between_tenants_is_rejected()
    {
        var current = NewKey("k1", Now);
        SigningKeyRotation.ActivateFirst(current, Now.AddHours(1));
        var next = NewKey("k2", Now, Guid.CreateVersion7());

        Assert.Throws<DomainException>(() =>
            SigningKeyRotation.Rotate(current, next, TokenLifetime, Skew, Now.AddHours(2)));
    }

    [Fact]
    public void Emergency_removal_leaves_the_jwks_at_once()
    {
        var key = NewKey("k1", Now);
        SigningKeyRotation.ActivateFirst(key, Now.AddHours(1));

        key.RemoveNow(Now.AddHours(2));

        Assert.False(key.CanSign);
        Assert.False(key.IsPublished(Now.AddHours(2)));
    }

    [Fact]
    public void Private_key_material_is_rejected_as_a_reference()
    {
        Assert.Throws<DomainException>(() => SigningKey.Create(
            Guid.CreateVersion7(),
            TenantId,
            "k1",
            "{\"kty\":\"RSA\"}",
            "-----BEGIN PRIVATE KEY-----\nMIIE...",
            CacheLifetime,
            Now));
    }

    [Fact]
    public void Algorithm_is_RS256()
    {
        Assert.Equal("RS256", SigningKey.Algorithm);
    }
}
