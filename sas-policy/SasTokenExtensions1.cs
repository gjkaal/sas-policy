using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace N2.Security.Sas;

public static class SasTokenExtensions
{
    public static IServiceCollection AddSasTokensFromSettings(this IServiceCollection services)
    {
        services.TryAddSingleton<ISasPolicyRepository, SasPolicyFromSettings>();
        services.TryAddSingleton<ISasTokenValidator, SasTokenValidator>();
        return services;
    }

    public static IApplicationBuilder UseSasTokens(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SasTokenMiddleware>();
    }
}
