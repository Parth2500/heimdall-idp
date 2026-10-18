using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Application.Settings;
using Heimdall.Application.Tokens;
using Heimdall.Application.Users;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Heimdall.Application;

public static class DependencyInjection
{
    /// <summary>
    /// Registers the use cases. The stores, the signer, and the key store come from Infrastructure.
    /// The platform limits use the defaults unless the caller registered a configured instance first.
    /// </summary>
    public static IServiceCollection AddHeimdallApplication(this IServiceCollection services)
    {
        services.TryAddSingleton(new PlatformLimits());
        services.TryAddSingleton(new PasswordHashingOptions());
        services.AddScoped<ClientAuthenticator>();
        services.AddScoped<ClientCredentialsGrant>();
        services.AddScoped<SigningKeyService>();
        services.AddScoped<UserAuthenticator>();
        return services;
    }
}
