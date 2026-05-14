using Canary.AspNetCore.Middleware;
using Microsoft.AspNetCore.Builder;

namespace Canary.AspNetCore.Extensions;

/// <summary>
/// Pipeline registration helpers for the canary middleware.
/// </summary>
public static class CanaryApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the <see cref="CanaryAuthMiddleware"/> to the pipeline. MUST be
    /// registered AFTER <see cref="AuthorizationAppBuilderExtensions.UseAuthorization"/>
    /// so <see cref="Microsoft.AspNetCore.Http.HttpContext.User"/> is
    /// populated when the role check runs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Registering before authentication/authorization would let
    /// unauthenticated callers probe canary behavior via response-timing
    /// differences. The class-level remarks on
    /// <see cref="CanaryAuthMiddleware"/> document the security model;
    /// this helper enforces the placement by name.
    /// </para>
    /// </remarks>
    public static IApplicationBuilder UseCanaryAuth(this IApplicationBuilder app)
    {
        return app.UseMiddleware<CanaryAuthMiddleware>();
    }
}
