namespace Heimdall.Application.Keys;

/// <summary>
/// The tenant has no active signing key. Heimdall issues no token without one (fail closed).
/// This is a server fault, not a client error.
/// </summary>
public sealed class SigningKeyUnavailableException : Exception
{
    public SigningKeyUnavailableException()
    {
    }

    public SigningKeyUnavailableException(string message)
        : base(message)
    {
    }

    public SigningKeyUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public SigningKeyUnavailableException(Guid tenantId)
        : base($"Tenant {tenantId} has no active signing key.")
    {
        TenantId = tenantId;
    }

    public Guid? TenantId { get; }
}
