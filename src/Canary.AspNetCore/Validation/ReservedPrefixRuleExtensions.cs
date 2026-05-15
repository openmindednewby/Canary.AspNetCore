using System.Text.RegularExpressions;
using Canary.AspNetCore.Configuration;
using Canary.AspNetCore.Context;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Canary.AspNetCore.Validation;

/// <summary>
/// FluentValidation rule extensions that reject input matching the canary
/// reserved-prefix scheme. Applied to tenant names, usernames, menu names,
/// and any other user-controlled field that the cleanup endpoint sweeps
/// by name prefix.
/// </summary>
/// <remarks>
/// <para>
/// The validator emits a <see cref="CanaryErrorCodes.ReservedPrefix"/>
/// error code so frontends can surface a stable diagnostic without
/// brittle string matching on the message. The error message is
/// intentionally cryptic — the canary prefix is an internal convention
/// and we don't want to give a real attacker a reference manual.
/// </para>
/// <para>
/// The default pattern compiles once at module load and is shared across
/// all validator instances. Custom patterns recompile per-validator —
/// only override the default if you know you need a different rule.
/// </para>
/// <para>
/// <b>Canary bypass:</b> when the current HTTP request has been tagged as
/// canary by <see cref="Middleware.CanaryAuthMiddleware"/> (i.e.
/// <see cref="ICanaryRunContext.IsCanary"/> is <see langword="true"/> for
/// the request), the rule is skipped. This is the whole point of the
/// canary plumbing — canary setup/teardown SHOULD create entities with the
/// reserved prefix; real customer requests still get the 400. The check
/// reads <see cref="HttpContextAccessor"/>, which is populated by
/// <see cref="Extensions.CanaryApplicationBuilderExtensions.UseCanaryAuth"/>
/// at pipeline registration. When the accessor is null (unit tests that
/// don't run the middleware pipeline) the bypass is inert and the rule
/// behaves as before.
/// </para>
/// </remarks>
public static class ReservedPrefixRuleExtensions
{
    // Compile the default pattern once. RegexOptions.Compiled is overkill
    // for a validator that runs on every create/update call - the JIT is
    // fast enough at small regexes - but harmless and consistent with the
    // existing Validation.Defaults patterns in the stack.
    private static readonly Regex DefaultReservedPrefixRegex =
        new(@"^e2ec-[0-9a-f]{8}-", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Process-wide accessor used by the rule to look up the current
    /// request's <see cref="ICanaryRunContext"/>. Populated by
    /// <see cref="Extensions.CanaryApplicationBuilderExtensions.UseCanaryAuth"/>
    /// at pipeline-registration time so the FluentValidation
    /// <c>Must</c> callback — which has no
    /// direct DI access — can still resolve the per-request context.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Static state is intentional. FluentValidation's <c>Must</c> callback
    /// runs in the same scope as the validator and validators in the
    /// FastEndpoints stack are singletons constructed from a default ctor,
    /// so per-instance DI is not an option here. Setting the accessor once
    /// at startup gives every validator the same lookup path — identical
    /// to how Serilog's static <c>Log.Logger</c> is wired.
    /// </para>
    /// <para>
    /// Unit tests can set this directly to exercise both branches (canary
    /// bypass vs. real-customer enforcement). When null, the rule never
    /// bypasses — the legacy 1.0.0 behavior.
    /// </para>
    /// </remarks>
    public static IHttpContextAccessor? HttpContextAccessor { get; set; }

    /// <summary>
    /// Rejects input matching the canary reserved-prefix pattern with
    /// HTTP 400 + error code <see cref="CanaryErrorCodes.ReservedPrefix"/>.
    /// Bypassed when the current request is a canary request (see
    /// class-level remarks).
    /// </summary>
    /// <typeparam name="T">The request type the rule is attached to.</typeparam>
    /// <typeparam name="TProperty">The property type — typically <see cref="string"/> or <see cref="string"/>?.</typeparam>
    /// <param name="rule">The FluentValidation rule builder.</param>
    /// <param name="options">
    /// Optional <see cref="CanaryOptions"/> override. When null, the default
    /// pattern (<c>^e2ec-[0-9a-f]{8}-</c>) is used. Pass an override only
    /// for services that customize <see cref="CanaryOptions.ReservedPrefixPattern"/>
    /// — the default is correct for the entire stack.
    /// </param>
    /// <remarks>
    /// Generic over <typeparamref name="TProperty"/> so the same extension
    /// works for both <see cref="string"/> and <see cref="string"/>? properties
    /// without separate overloads — separate overloads would collide at runtime
    /// because NRT annotations are metadata-only. The validator coerces the
    /// value via <c>ToString()</c> which is safe for all expected inputs.
    /// </remarks>
    public static IRuleBuilderOptions<T, TProperty> MustNotMatchReservedPrefix<T, TProperty>(
        this IRuleBuilder<T, TProperty> rule,
        CanaryOptions? options = null)
    {
        var regex = options is null
            ? DefaultReservedPrefixRegex
            : new Regex(options.ReservedPrefixPattern, RegexOptions.CultureInvariant);

        return rule
            .Must(value =>
            {
                // Canary bypass: when the current request has been authenticated
                // as canary by CanaryAuthMiddleware, the reserved-prefix rule is
                // exactly what we want to skip — the canary infrastructure
                // ITSELF needs to create entities with the e2ec- prefix so the
                // orphan-cleanup sweep can find them later. Real customers
                // (no canary header / no superUser JWT) never trip this branch
                // because CanaryAuthMiddleware leaves IsCanary=false for them.
                if (IsCurrentRequestCanary())
                {
                    return true;
                }

                var asString = value?.ToString();
                return string.IsNullOrEmpty(asString) || !regex.IsMatch(asString);
            })
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix)
            .WithMessage("This name uses a reserved prefix and is not allowed.");
    }

    /// <summary>
    /// Looks up <see cref="ICanaryRunContext"/> from the current request's
    /// service scope. Returns <see langword="false"/> when the accessor
    /// hasn't been wired (unit tests that don't run the pipeline), when
    /// there is no active HTTP request (background work, hosted services),
    /// or when the context is not registered.
    /// </summary>
    /// <remarks>
    /// Resolving from <see cref="HttpContext.RequestServices"/> (the
    /// per-request scope) — NOT <c>app.ApplicationServices</c> (the root
    /// container) — is critical: <see cref="CanaryRunContext"/> is registered
    /// scoped, so root-scope resolution would either throw or hand back a
    /// shared instance with leaked IsCanary=true between requests.
    /// </remarks>
    private static bool IsCurrentRequestCanary()
    {
        var httpContext = HttpContextAccessor?.HttpContext;
        if (httpContext is null)
        {
            return false;
        }

        var canaryContext = httpContext.RequestServices.GetService<ICanaryRunContext>();
        return canaryContext?.IsCanary == true;
    }
}
