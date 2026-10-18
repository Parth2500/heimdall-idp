namespace Heimdall.IntegrationTests;

/// <summary>
/// A test that needs Docker. On a machine without Docker it is skipped. In CI (CI=true) it is never skipped,
/// so a missing Docker fails the build instead of passing quietly.
/// </summary>
public sealed class DockerFactAttribute : FactAttribute
{
    public DockerFactAttribute()
    {
        if (!DockerAvailability.IsAvailable && !DockerAvailability.IsCi)
        {
            Skip = "Docker is not available on this machine. These tests run in CI.";
        }
    }
}

/// <summary>The <see cref="TheoryAttribute"/> form of <see cref="DockerFactAttribute"/>.</summary>
public sealed class DockerTheoryAttribute : TheoryAttribute
{
    public DockerTheoryAttribute()
    {
        if (!DockerAvailability.IsAvailable && !DockerAvailability.IsCi)
        {
            Skip = "Docker is not available on this machine. These tests run in CI.";
        }
    }
}

internal static class DockerAvailability
{
    public static bool IsCi { get; } =
        string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase);

    public static bool IsAvailable { get; } = Detect();

    private static bool Detect()
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DOCKER_HOST")))
        {
            return true;
        }

        try
        {
            return OperatingSystem.IsWindows()
                ? Directory.GetFiles(@"\\.\pipe\").Any(p => p.Contains("docker_engine", StringComparison.OrdinalIgnoreCase))
                : File.Exists("/var/run/docker.sock");
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
