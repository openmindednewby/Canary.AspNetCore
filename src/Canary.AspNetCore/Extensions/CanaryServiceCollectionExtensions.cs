using Canary.AspNetCore.Configuration;
using Canary.AspNetCore.Context;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Canary.AspNetCore.Extensions;

/// <summary>
/// DI registration helpers for the canary middleware infrastructure.
/// </summary>
public static class CanaryServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="CanaryOptions"/> (bound to the "Canary"
    /// configuration section) and the scoped <see cref="ICanaryRunContext"/>
    /// accessor. Call this before the WebApplication is built.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">App configuration root.</param>
    /// <param name="configure">Optional code-level option override.</param>
    /// <remarks>
    /// <para>
    /// Pair with <see cref="CanaryApplicationBuilderExtensions.UseCanaryAuth"/>
    /// in the middleware pipeline. The middleware reads
    /// <see cref="ICanaryRunContext"/> from DI and mutates the concrete
    /// instance — endpoints inject the interface for read-only access.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddCanaryAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<CanaryOptions>? configure = null)
    {
        var section = configuration.GetSection(CanaryOptions.SectionName);

        services
            .AddOptions<CanaryOptions>()
            .Bind(section)
            .Configure(opts =>
            {
                configure?.Invoke(opts);
            });

        // CanaryRunContext is scoped so the middleware can mutate it once
        // per request without leaking state across requests. The concrete
        // type is registered separately from the interface so the middleware
        // can resolve the mutable shape while consumers see the read-only
        // interface.
        services.AddScoped<CanaryRunContext>();
        services.AddScoped<ICanaryRunContext>(sp => sp.GetRequiredService<CanaryRunContext>());

        // IHttpContextAccessor is required for the reserved-prefix validator
        // to look up the per-request ICanaryRunContext and skip the rule for
        // canary requests. AddHttpContextAccessor is idempotent (it uses
        // TryAddSingleton internally) so calling it here is safe even if the
        // consumer has already registered it elsewhere.
        services.AddHttpContextAccessor();

        return services;
    }
}
