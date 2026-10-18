namespace Heimdall.Application.Common;

/// <summary>
/// A database constraint refused a change because another caller made a conflicting change first, for example a
/// second active key for one tenant. The losing caller changed nothing.
/// </summary>
public sealed class ConcurrentUpdateException : Exception
{
    public ConcurrentUpdateException()
    {
    }

    public ConcurrentUpdateException(string message)
        : base(message)
    {
    }

    public ConcurrentUpdateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
