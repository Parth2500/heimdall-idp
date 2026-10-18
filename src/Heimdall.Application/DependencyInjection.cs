using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Application.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.Application;

public static class DependencyInjection
{
    /// <summary>Registers the use cases. The stores, the signer, and the key store come from Infrastructure.</summary>
    public static IServiceCollection AddHeimdallApplication(this IServiceCollection services)
    {
        services.AddScoped<ClientAuthenticator>();
        services.AddScoped<ClientCredentialsGrant>();
        services.AddScoped<SigningKeyService>();
        return services;
    }
}
