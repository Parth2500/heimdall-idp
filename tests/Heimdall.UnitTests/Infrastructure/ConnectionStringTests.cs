using Heimdall.Infrastructure;
using Npgsql;

namespace Heimdall.UnitTests.Infrastructure;

public class ConnectionStringTests
{
    [Fact]
    public void GSS_encryption_is_off_by_default()
    {
        var result = new NpgsqlConnectionStringBuilder(
            DependencyInjection.WithoutGssEncryption("Host=db;Database=heimdall;Username=app;Password=p;SSL Mode=Require"));

        Assert.Equal(GssEncryptionMode.Disable, result.GssEncryptionMode);
        Assert.Equal("db", result.Host);
        Assert.Equal("heimdall", result.Database);
        Assert.Equal("app", result.Username);
        Assert.Equal("p", result.Password);
        Assert.Equal(SslMode.Require, result.SslMode);
    }

    [Theory]
    [InlineData("Host=db;GSS Encryption Mode=Prefer")]
    [InlineData("Host=db;gssencryptionmode=Prefer")]
    public void Explicit_GSS_setting_is_kept(string connectionString)
    {
        var result = new NpgsqlConnectionStringBuilder(DependencyInjection.WithoutGssEncryption(connectionString));

        Assert.Equal(GssEncryptionMode.Prefer, result.GssEncryptionMode);
    }
}
