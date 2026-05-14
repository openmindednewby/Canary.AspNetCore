namespace Canary.AspNetCore.Context;

/// <summary>
/// Default implementation of <see cref="ICanaryRunContext"/>. Mutable
/// via <see cref="Activate(string)"/> so the middleware can populate it;
/// consumers should depend on the read-only <see cref="ICanaryRunContext"/>
/// interface for branching logic.
/// </summary>
/// <remarks>
/// <para>
/// Registered as scoped — one instance per HTTP request. Lives in
/// <c>Canary.AspNetCore</c> rather than the consumer assembly so the
/// middleware can mutate it via the concrete type without exposing
/// setters on the public interface.
/// </para>
/// <para>
/// The class and <see cref="Activate(string)"/> are <c>public</c> rather
/// than <c>internal</c> so the package can be consumed as a NuGet package
/// without a hardcoded <c>InternalsVisibleTo</c> for every consumer's test
/// project. Endpoints still inject <see cref="ICanaryRunContext"/> — the
/// concrete type being public only widens what middleware-level tests can
/// construct, not the contract endpoints depend on.
/// </para>
/// </remarks>
public sealed class CanaryRunContext : ICanaryRunContext
{
    public bool IsCanary { get; private set; }

    public string? RunId { get; private set; }

    public string? RunIdShort { get; private set; }

    /// <summary>
    /// Populates the context with a validated run identifier. Called by
    /// <see cref="Middleware.CanaryAuthMiddleware"/> after the JWT role check
    /// has passed.
    /// </summary>
    public void Activate(string runId)
    {
        if (string.IsNullOrEmpty(runId))
            throw new ArgumentException("RunId cannot be empty when activating canary context", nameof(runId));

        IsCanary = true;
        RunId = runId;
        RunIdShort = runId.Length >= 8 ? runId.Substring(0, 8) : runId;
    }
}
