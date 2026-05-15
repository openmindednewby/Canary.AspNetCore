using Canary.AspNetCore.Middleware;
using Canary.AspNetCore.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

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
    /// <para>
    /// As a side effect, this call also stashes the resolved
    /// <see cref="IHttpContextAccessor"/> on
    /// <see cref="ReservedPrefixRuleExtensions.HttpContextAccessor"/> so the
    /// <c>MustNotMatchReservedPrefix</c> rule can look up the per-request
    /// <see cref="Context.ICanaryRunContext"/> and bypass itself for canary
    /// requests. Without this wiring, the validator would (correctly) reject
    /// the canary infrastructure's OWN setup requests with HTTP 400 +
    /// <c>RESERVED_PREFIX</c>.
    /// </para>
    /// </remarks>
    public static IApplicationBuilder UseCanaryAuth(this IApplicationBuilder app)
    {
        // The validator needs an IHttpContextAccessor to look up the
        // per-request canary context. Stash it on the static accessor here
        // rather than asking every consumer to wire it themselves — the
        // accessor is a singleton, so capturing it once at pipeline-build
        // time is safe. Tests that don't call UseCanaryAuth get the null
        // default and the legacy "always enforce" behavior.
        ReservedPrefixRuleExtensions.HttpContextAccessor =
            app.ApplicationServices.GetRequiredService<IHttpContextAccessor>();

        return app.UseMiddleware<CanaryAuthMiddleware>();
    }
}
