using System.Text.RegularExpressions;
using Canary.AspNetCore.Configuration;
using FluentValidation;

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
    /// Rejects input matching the canary reserved-prefix pattern with
    /// HTTP 400 + error code <see cref="CanaryErrorCodes.ReservedPrefix"/>.
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
                var asString = value?.ToString();
                return string.IsNullOrEmpty(asString) || !regex.IsMatch(asString);
            })
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix)
            .WithMessage("This name uses a reserved prefix and is not allowed.");
    }
}
