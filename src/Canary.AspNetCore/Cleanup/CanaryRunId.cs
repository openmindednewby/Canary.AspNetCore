using System.Text.RegularExpressions;

namespace Canary.AspNetCore.Cleanup;

/// <summary>
/// Shared helpers for the canary test-data cleanup endpoints every service ships
/// (<c>DELETE /internal/canary-cleanup</c>). Centralises the three pieces that
/// were copy-pasted near-verbatim across the SaaS services: the strict UUID
/// validation of the supplied <c>runId</c>, the <c>runId</c> → 8-char sweep-key
/// derivation, and the realm role a caller must present.
/// <para>
/// Deliberately dependency-free (no EF Core): the per-entity
/// <c>IgnoreQueryFilters().Where(x =&gt; x.CanaryRunIdShort == short)</c> +
/// Load/RemoveRange delete stays in each endpoint, so adopting this helper never
/// changes a service's response shape or couples this package to EF Core.
/// </para>
/// </summary>
public static partial class CanaryRunId
{
    /// <summary>
    /// The realm role a canary-cleanup caller must present. Matches
    /// <c>IdentityRoles.Administrator</c> ("superUser") in TenantService — the
    /// constant the per-service endpoints used to each declare as a literal.
    /// </summary>
    public const string RoleRequired = "superUser";

    /// <summary>Length of the short sweep key (first 8 hex chars of the UUID).</summary>
    public const int ShortLength = 8;

    [GeneratedRegex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        RegexOptions.CultureInvariant)]
    private static partial Regex UuidPattern();

    /// <summary>True when <paramref name="runId"/> is a well-formed UUID.</summary>
    public static bool IsValid(string? runId) =>
        !string.IsNullOrWhiteSpace(runId) && UuidPattern().IsMatch(runId);

    /// <summary>
    /// The 8-char sweep key (first <see cref="ShortLength"/> hex chars). Throws
    /// <see cref="ArgumentException"/> when <paramref name="runId"/> is not a
    /// valid UUID — endpoints should <see cref="IsValid"/> first and return 400.
    /// </summary>
    public static string ToShort(string runId)
    {
        if (!IsValid(runId))
        {
            throw new ArgumentException("runId must be a UUID.", nameof(runId));
        }

        return runId[..ShortLength];
    }

    /// <summary>
    /// Validate and derive the sweep key in one call. Returns false (with
    /// <paramref name="runIdShort"/> = null) for a malformed UUID, so an endpoint
    /// can branch straight to its 400 INVALID_RUN_ID response.
    /// </summary>
    public static bool TryToShort(string? runId, out string? runIdShort)
    {
        if (!IsValid(runId))
        {
            runIdShort = null;
            return false;
        }

        runIdShort = runId![..ShortLength];
        return true;
    }
}
