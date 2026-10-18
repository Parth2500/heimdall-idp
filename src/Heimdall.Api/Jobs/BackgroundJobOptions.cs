namespace Heimdall.Api.Jobs;

/// <summary>Switches the background loops of the jobs. A test host turns them off and runs each pass itself.</summary>
public sealed class BackgroundJobOptions
{
    public const string SectionName = "Heimdall:Jobs";

    /// <summary>When false, the loops of <see cref="SigningKeyJob"/> and <see cref="PurgeJob"/> do not start.</summary>
    public bool Enabled { get; set; } = true;
}
