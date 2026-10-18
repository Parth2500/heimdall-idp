using Heimdall.Application.Authorization;
using Heimdall.Application.Clients;
using Heimdall.Application.Keys;
using Heimdall.Application.Sessions;
using Heimdall.Application.Settings;
using Heimdall.Application.Tokens;
using Heimdall.Application.UserInfo;
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
        services.AddScoped<AuthorizationCodeGrant>();
        services.AddScoped<RefreshTokenGrant>();
        services.AddScoped<TokenRevocation>();
        services.AddScoped<UserInfoService>();
        services.AddScoped<SigningKeyService>();
        services.AddScoped<UserAuthenticator>();
        services.AddScoped<SessionService>();
        services.AddScoped<AuthorizationService>();
        services.AddScoped<ConsentService>();
        return services;
    }
}
