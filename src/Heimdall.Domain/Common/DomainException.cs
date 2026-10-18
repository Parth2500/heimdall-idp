namespace Heimdall.Domain.Common;

/// <summary>A business rule of the domain was broken.</summary>
public sealed class DomainException : Exception
{
    public DomainException(string message) : base(message)
    {
    }
}
