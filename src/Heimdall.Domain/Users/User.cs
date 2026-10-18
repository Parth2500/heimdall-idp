using Heimdall.Domain.Common;

namespace Heimdall.Domain.Users;

public enum UserStatus
{
    Active,
    Disabled,
}

public sealed class User
{
    private User(
        Guid id,
        Guid tenantId,
        string email,
        string emailNormalized,
        string passwordHash,
        UserStatus status,
        DateTimeOffset createdAt)
    {
        Id = id;
        TenantId = tenantId;
        Email = email;
        EmailNormalized = emailNormalized;
        PasswordHash = passwordHash;
        Status = status;
        CreatedAt = createdAt;
        PasswordChangedAt = createdAt;
    }

    /// <summary>The value of the <c>sub</c> claim. It never changes and is never reused.</summary>
    public Guid Id { get; }

    public Guid TenantId { get; }

    public string Email { get; }

    /// <summary>Lowercase form of the email. It is unique within a tenant.</summary>
    public string EmailNormalized { get; }

    /// <summary>An Argon2id hash. The domain never sees the plain password (D3).</summary>
    public string PasswordHash { get; private set; }

    public UserStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; }

    /// <summary>Sessions created before this time are no longer valid.</summary>
    public DateTimeOffset PasswordChangedAt { get; private set; }

    public static string NormalizeEmail(string email) => Guard.NotBlank(email, nameof(email)).ToLowerInvariant();

    public static User Create(Guid id, Guid tenantId, string email, string passwordHash, DateTimeOffset now)
    {
        Guard.NotEmpty(id, nameof(id));
        Guard.NotEmpty(tenantId, nameof(tenantId));

        var trimmed = Guard.NotBlank(email, nameof(email));
        var at = trimmed.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0 || at == trimmed.Length - 1 || trimmed.Any(char.IsWhiteSpace))
        {
            throw new DomainException("The email address is not valid.");
        }

        return new User(
            id,
            tenantId,
            trimmed,
            NormalizeEmail(trimmed),
            Guard.NotBlank(passwordHash, nameof(passwordHash)),
            UserStatus.Active,
            now);
    }

    public void ChangePassword(string newPasswordHash, DateTimeOffset now)
    {
        PasswordHash = Guard.NotBlank(newPasswordHash, nameof(newPasswordHash));
        PasswordChangedAt = now;
    }

    /// <summary>
    /// Replaces the hash of the same password with a hash that uses stronger parameters. The password did not
    /// change, so <see cref="PasswordChangedAt"/> stays and the user's sessions stay valid.
    /// </summary>
    public void UpgradePasswordHash(string newPasswordHash) =>
        PasswordHash = Guard.NotBlank(newPasswordHash, nameof(newPasswordHash));

    public void Disable() => Status = UserStatus.Disabled;

    public void Enable() => Status = UserStatus.Active;
}
