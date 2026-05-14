using Canary.AspNetCore.Configuration;
using Canary.AspNetCore.Context;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog.Context;

namespace Canary.AspNetCore.Middleware;

/// <summary>
/// ASP.NET Core middleware that gates the <c>X-Canary-Run-Id</c> header on a
/// valid superUser JWT. Without the role, the header alone does nothing
/// (and is rejected with HTTP 403). With the role, the request is tagged
/// as canary — visible to downstream code via <see cref="ICanaryRunContext"/>
/// and visible to observability via a Serilog scope.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pipeline placement (critical):</b> Register this middleware AFTER
/// <see cref="Microsoft.AspNetCore.Builder.AuthorizationAppBuilderExtensions.UseAuthorization"/>
/// so <see cref="HttpContext.User"/> is populated when the role check runs.
/// Registering it before authentication would let unauthenticated callers
/// probe canary behavior — explicitly forbidden by the design.
/// </para>
/// <para>
/// <b>Behavior matrix:</b>
/// <list type="bullet">
///   <item><description>No canary header → no-op, request flows normally.</description></item>
///   <item><description>Header + valid UUID + superUser role → activate canary context, push Serilog scope, continue.</description></item>
///   <item><description>Header + valid UUID + missing/wrong role → 403 INVALID_CANARY_AUTH.</description></item>
///   <item><description>Header + malformed UUID → 400 INVALID_CANARY_RUN_ID.</description></item>
/// </list>
/// </para>
/// <para>
/// <b>Logging:</b> when canary mode activates, a Serilog <c>LogContext</c>
/// property <c>canary_run_id</c> is pushed for the duration of the request.
/// Every Serilog log line emitted downstream will carry the property,
/// allowing log filtering and Loki queries to scope to a specific run.
/// </para>
/// </remarks>
public sealed class CanaryAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly CanaryOptions _options;
    private readonly ILogger<CanaryAuthMiddleware> _logger;

    /// <summary>
    /// Creates the middleware with the resolved <see cref="CanaryOptions"/>.
    /// </summary>
    public CanaryAuthMiddleware(
        RequestDelegate next,
        IOptions<CanaryOptions> options,
        ILogger<CanaryAuthMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Inspects the request for the canary header and gates it on the
    /// configured role. See class-level remarks for the behavior matrix.
    /// </summary>
    public async Task InvokeAsync(HttpContext context, ICanaryRunContext canaryContext)
    {
        if (!TryGetCanaryHeader(context, out var rawHeader))
        {
            // Default path: no header, no canary tagging — flow through.
            await _next(context);
            return;
        }

        // Defense-in-depth: validate header format BEFORE checking auth so
        // malformed headers fail fast with a 400, not 403. (Order does not
        // change the security story — the role check below is the gate that
        // matters.)
        if (!Guid.TryParse(rawHeader, out var runIdGuid))
        {
            _logger.LogWarning(
                "canary_header_malformed path={Path} headerValueLength={Length}",
                context.Request.Path.Value,
                rawHeader.Length);
            await WriteFailureAsync(context, StatusCodes.Status400BadRequest,
                CanaryErrorCodes.InvalidRunId,
                $"The {_options.HeaderName} header must be a UUID.");
            return;
        }

        // Critical gate: superUser role required. Without it, the header is
        // a privileged operation the caller cannot perform — return 403, not
        // 401, because the request IS authenticated (or, when unauthenticated,
        // the User.Identity?.IsAuthenticated check folds back to the same
        // result without leaking whether the role check or the auth check
        // failed first).
        if (!IsAuthorizedForCanary(context))
        {
            _logger.LogWarning(
                "canary_header_unauthorized path={Path} isAuthenticated={Authenticated} requiredRole={Role}",
                context.Request.Path.Value,
                context.User?.Identity?.IsAuthenticated ?? false,
                _options.RequiredRole);
            await WriteFailureAsync(context, StatusCodes.Status403Forbidden,
                CanaryErrorCodes.InvalidCanaryAuth,
                $"The {_options.HeaderName} header is only valid when accompanied by a {_options.RequiredRole} JWT.");
            return;
        }

        // Canary tagged. Populate the per-request context, push the Serilog
        // scope, and continue. The Serilog property name is snake_case to
        // match the existing log-property convention used by Logging.Client.
        var runId = runIdGuid.ToString("D");
        if (canaryContext is CanaryRunContext concrete)
        {
            concrete.Activate(runId);
        }

        // Surface the run id on the response so the E2E runner has confirmation
        // its header was honored. The header is harmless to expose — it's a value
        // the caller already supplied.
        context.Response.Headers["X-Canary-Run-Id"] = runId;

        using (LogContext.PushProperty("canary_run_id", runId))
        {
            _logger.LogInformation(
                "canary_request_tagged path={Path} method={Method} runId={RunId}",
                context.Request.Path.Value,
                context.Request.Method,
                runId);
            await _next(context);
        }
    }

    private bool TryGetCanaryHeader(HttpContext context, out string value)
    {
        if (context.Request.Headers.TryGetValue(_options.HeaderName, out var values))
        {
            var first = values.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(first))
            {
                value = first;
                return true;
            }
        }
        value = string.Empty;
        return false;
    }

    private bool IsAuthorizedForCanary(HttpContext context)
    {
        var user = context.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            return false;
        }
        return user.IsInRole(_options.RequiredRole);
    }

    private static async Task WriteFailureAsync(
        HttpContext context,
        int statusCode,
        string errorCode,
        string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json; charset=utf-8";
        var payload = $"{{\"errorCode\":\"{errorCode}\",\"errorMessage\":\"{message.Replace("\"", "\\\"")}\"}}";
        await context.Response.WriteAsync(payload);
    }
}
