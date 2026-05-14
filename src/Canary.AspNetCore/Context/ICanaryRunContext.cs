namespace Canary.AspNetCore.Context;

/// <summary>
/// Per-request accessor for canary state. Endpoints inject this when they
/// need to branch behavior based on whether the current request is part of
/// a canary E2E run.
/// </summary>
/// <remarks>
/// <para>
/// The instance is registered as scoped — values are populated by
/// <see cref="Middleware.CanaryAuthMiddleware"/> after the JWT has been
/// validated and the canary header has been inspected. Endpoints that run
/// BEFORE the middleware (none in normal pipelines) will see the default
/// <c>IsCanary == false</c> state.
/// </para>
/// <para>
/// Slice 2-6 services use this for the behavioral mock paths — PaymentService
/// checks <see cref="IsCanary"/> before calling Stripe; NotificationService
/// checks it before dispatching SMTP/SMS. IdentityService (slice 1) only
/// uses it indirectly via the Serilog scope + Prometheus label that the
/// middleware pushes.
/// </para>
/// </remarks>
public interface ICanaryRunContext
{
    /// <summary>
    /// <see langword="true"/> when the current request was tagged as a canary
    /// — i.e. it carried the canary header AND a valid <c>superUser</c> JWT.
    /// </summary>
    bool IsCanary { get; }

    /// <summary>
    /// The full canary run identifier (UUID string), or <see langword="null"/>
    /// when the request is not a canary. Use this for log correlation and
    /// cleanup-endpoint addressing.
    /// </summary>
    string? RunId { get; }

    /// <summary>
    /// The first 8 hex characters of <see cref="RunId"/>, used as the
    /// short-form key in the <c>e2ec-{runId8}-</c> name prefix scheme. Null
    /// when <see cref="IsCanary"/> is <see langword="false"/>.
    /// </summary>
    string? RunIdShort { get; }
}
