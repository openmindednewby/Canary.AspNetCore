namespace Canary.AspNetCore.Configuration;

/// <summary>
/// Strongly-typed configuration for the canary middleware + reserved-prefix
/// validator. Bound to the <c>Canary</c> configuration section.
/// </summary>
/// <remarks>
/// <para>
/// All settings have sensible defaults so the typical consumer can register
/// the middleware without any configuration. Override individual settings
/// per-service if the canary protocol ever differs (e.g. a service-specific
/// header name).
/// </para>
/// <para>
/// The defaults match the contract documented in
/// <c>docs/Tasks/IN_PROGRESS/e2e-multi-environment-execution.md</c> "Canary
/// infrastructure" — header name <c>X-Canary-Run-Id</c>, required role
/// <c>superUser</c>, reserved prefix regex <c>^e2ec-[0-9a-f]{8}-</c>.
/// </para>
/// </remarks>
public sealed class CanaryOptions
{
    /// <summary>
    /// The configuration section name bound by <c>AddCanaryAuth</c>.
    /// </summary>
    public const string SectionName = "Canary";

    /// <summary>
    /// HTTP header that carries the canary run identifier. A request with
    /// this header AND a valid <see cref="RequiredRole"/> JWT is treated as
    /// canary; a request with this header but no/wrong role is rejected with
    /// HTTP 403.
    /// </summary>
    public string HeaderName { get; set; } = "X-Canary-Run-Id";

    /// <summary>
    /// The Keycloak realm-role that must be present on the bearer token for
    /// the canary header to take effect. Defaults to <c>superUser</c>, which
    /// matches <c>IdentityRoles.Administrator</c> across every service in
    /// the stack.
    /// </summary>
    public string RequiredRole { get; set; } = "superUser";

    /// <summary>
    /// Regex that names/usernames must NOT match. Validators using
    /// <c>MustNotMatchReservedPrefix</c> reject inputs matching this
    /// pattern with HTTP 400 + error code <see cref="CanaryErrorCodes.ReservedPrefix"/>.
    /// </summary>
    /// <remarks>
    /// Default matches <c>e2ec-{8-hex-chars}-</c>, the canary name-prefix
    /// scheme. The 8-hex segment is the first 8 chars of a v4 UUID — i.e.
    /// the run identifier — so a real customer's name accidentally matching
    /// this pattern would be ambiguous with canary-created data and would
    /// be swept by the orphan-cleanup CronJob. Validation closes that gap.
    /// </remarks>
    public string ReservedPrefixPattern { get; set; } = @"^e2ec-[0-9a-f]{8}-";
}

/// <summary>
/// Stable error codes surfaced by the canary middleware and validators.
/// </summary>
public static class CanaryErrorCodes
{
    /// <summary>HTTP 400 — caller supplied a name matching the canary reserved prefix.</summary>
    public const string ReservedPrefix = "RESERVED_PREFIX";

    /// <summary>HTTP 403 — canary header was present without a valid superUser JWT.</summary>
    public const string InvalidCanaryAuth = "INVALID_CANARY_AUTH";

    /// <summary>HTTP 400 — canary header value was not a well-formed UUID.</summary>
    public const string InvalidRunId = "INVALID_CANARY_RUN_ID";
}
