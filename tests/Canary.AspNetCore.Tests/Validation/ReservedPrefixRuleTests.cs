using System.Security.Claims;
using Canary.AspNetCore.Configuration;
using Canary.AspNetCore.Context;
using Canary.AspNetCore.Validation;
using FluentValidation;
using FluentValidation.TestHelper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;

namespace Canary.AspNetCore.Tests.Validation;

public sealed class ReservedPrefixRuleTests : IDisposable
{
    // The validator reads a process-wide IHttpContextAccessor on
    // ReservedPrefixRuleExtensions. To keep the legacy enforcement tests
    // isolated, snapshot the accessor on construct and restore on dispose
    // so the canary-bypass test below doesn't bleed into siblings (or vice
    // versa if xUnit parallelizes across collections in the future).
    private readonly IHttpContextAccessor? _originalAccessor =
        ReservedPrefixRuleExtensions.HttpContextAccessor;

    public void Dispose()
    {
        ReservedPrefixRuleExtensions.HttpContextAccessor = _originalAccessor;
    }

    private sealed record StringHolder(string? Value);

    private sealed class NullableValidator : AbstractValidator<StringHolder>
    {
        public NullableValidator()
        {
            RuleFor(x => x.Value).MustNotMatchReservedPrefix();
        }
    }

    private sealed record NonNullableHolder(string Value);

    private sealed class NonNullableValidator : AbstractValidator<NonNullableHolder>
    {
        public NonNullableValidator()
        {
            RuleFor(x => x.Value).MustNotMatchReservedPrefix();
        }
    }

    /// <summary>
    /// Stages an HTTP context whose RequestServices return the given
    /// <see cref="ICanaryRunContext"/>. Mirrors what
    /// <c>UseCanaryAuth</c> + the per-request DI scope produce in production.
    /// </summary>
    private static void StageHttpContextWithCanary(bool isCanary)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ICanaryRunContext>(new StubCanaryRunContext(isCanary));
        var provider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = provider };

        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        ReservedPrefixRuleExtensions.HttpContextAccessor = accessor;
    }

    /// <summary>
    /// Stages an HTTP context with IsCanary=false on the scoped context
    /// (so bypass A is closed) but an authenticated user whose identity
    /// name matches the canary prefix — the production shape of bypass B
    /// (SPA POST from a per-tenant admin whose username carries the e2ec-
    /// prefix). Pass <paramref name="username"/> = null to leave the user
    /// anonymous.
    /// </summary>
    private static void StageHttpContextWithUser(string? username)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ICanaryRunContext>(new StubCanaryRunContext(isCanary: false));
        var provider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = provider };
        if (!string.IsNullOrEmpty(username))
        {
            var identity = new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, username) },
                authenticationType: "Bearer");
            httpContext.User = new ClaimsPrincipal(identity);
        }

        ReservedPrefixRuleExtensions.HttpContextAccessor =
            new HttpContextAccessor { HttpContext = httpContext };
    }

    /// <summary>
    /// Clears any staged accessor so the validator falls back to the
    /// legacy enforce-always behavior (the typical state for tests that
    /// don't exercise the canary path).
    /// </summary>
    private static void ClearHttpContext()
    {
        ReservedPrefixRuleExtensions.HttpContextAccessor = null;
    }

    private sealed class StubCanaryRunContext : ICanaryRunContext
    {
        public StubCanaryRunContext(bool isCanary)
        {
            IsCanary = isCanary;
            RunId = isCanary ? "abc12345-aaaa-bbbb-cccc-1234567890ab" : null;
            RunIdShort = isCanary ? "abc12345" : null;
        }

        public bool IsCanary { get; }
        public string? RunId { get; }
        public string? RunIdShort { get; }
    }

    // ---------------------------------------------------------------------------
    // Default pattern: ^e2ec-[0-9a-f]{8}-
    // ---------------------------------------------------------------------------

    [Theory]
    [InlineData("e2ec-a1b2c3d4-foo")]
    [InlineData("e2ec-deadbeef-Test Tenant")]
    [InlineData("e2ec-00000000-")]
    [InlineData("e2ec-ffffffff-x")]
    public void Validate_MatchingPrefix_FailsWithReservedPrefixCode(string input)
    {
        ClearHttpContext();
        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(input));

        result.ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }

    [Theory]
    [InlineData("MyTenant")]
    [InlineData("Test User")]
    [InlineData("e2ec")]                                  // missing hex segment
    [InlineData("e2ec-abcd-")]                            // hex segment too short
    [InlineData("e2ec-abc12345")]                         // no trailing dash
    [InlineData("e2ec-abcdefgh-")]                        // 'g' / 'h' are not hex
    [InlineData("e2ec-A1B2C3D4-foo")]                     // uppercase hex (regex is case-sensitive on purpose)
    [InlineData("E2ec-a1b2c3d4-x")]                       // case-sensitive on the literal prefix too
    [InlineData("foo e2ec-a1b2c3d4-bar")]                 // matches but NOT at start
    [InlineData("")]
    public void Validate_NonMatching_Passes(string input)
    {
        ClearHttpContext();
        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(input));

        result.ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void Validate_NullValue_Passes()
    {
        ClearHttpContext();
        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(null));

        result.ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void Validate_NonNullableProperty_AlsoCoveredByGenericOverload()
    {
        // The generic <T, TProperty> overload covers both string and string?
        // properties without separate overloads (NRT is metadata-only so the
        // two would collide at runtime).
        ClearHttpContext();
        var validator = new NonNullableValidator();

        validator.TestValidate(new NonNullableHolder("e2ec-a1b2c3d4-x"))
            .ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);

        validator.TestValidate(new NonNullableHolder("MyTenant"))
            .ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    // ---------------------------------------------------------------------------
    // Custom pattern override.
    // ---------------------------------------------------------------------------

    [Fact]
    public void Validate_CustomPattern_HonoredOverDefault()
    {
        // Service-specific override - e.g. a future service that uses a
        // different prefix scheme.
        ClearHttpContext();
        var options = new CanaryOptions { ReservedPrefixPattern = @"^locked-" };

        var validator = new InlineValidator<StringHolder>();
        validator.RuleFor(x => x.Value).MustNotMatchReservedPrefix(options);

        validator.TestValidate(new StringHolder("locked-abc"))
            .ShouldHaveValidationErrorFor(x => x.Value);

        validator.TestValidate(new StringHolder("e2ec-a1b2c3d4-x"))
            .ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void ReservedPrefixErrorCode_IsStable()
    {
        // This constant is part of the public contract - frontend agents key
        // off it. Documenting it in a test keeps any rename loud.
        CanaryErrorCodes.ReservedPrefix.ShouldBe("RESERVED_PREFIX");
    }

    // ---------------------------------------------------------------------------
    // Canary bypass: when the current request is tagged as canary by
    // CanaryAuthMiddleware (IsCanary=true on the scoped ICanaryRunContext),
    // the rule MUST skip so the canary setup itself can create entities
    // carrying the reserved prefix.
    // ---------------------------------------------------------------------------

    [Theory]
    [InlineData("e2ec-a1b2c3d4-Test Tenant")]
    [InlineData("e2ec-deadbeef-Menu A")]
    [InlineData("e2ec-00000000-canary-user@example.com")]
    public void Validate_MatchingPrefix_InCanaryRequest_Bypassed(string input)
    {
        // Stage an HTTP context whose RequestServices return IsCanary=true
        // — i.e. CanaryAuthMiddleware has already accepted the
        // X-Canary-Run-Id header + superUser JWT on this request.
        StageHttpContextWithCanary(isCanary: true);

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(input));

        // The whole point of the bypass: the canary infrastructure's own
        // setup POSTs (e.g. multi-tenant.setup.ts -> POST tenants with name
        // "e2ec-{runId8}-e2e-TenantA") must NOT 400 with RESERVED_PREFIX.
        result.ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    [Theory]
    [InlineData("e2ec-a1b2c3d4-Test Tenant")]
    [InlineData("e2ec-deadbeef-Menu A")]
    public void Validate_MatchingPrefix_NonCanaryRequest_StillFails(string input)
    {
        // Same input, but the per-request ICanaryRunContext says IsCanary=false
        // — i.e. an authenticated real customer who didn't send the canary
        // header (or sent it without the superUser role and was already 403'd
        // upstream). The rule must still fire and emit 400 RESERVED_PREFIX.
        StageHttpContextWithCanary(isCanary: false);

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(input));

        result.ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }

    [Fact]
    public void Validate_HttpContextAccessorNull_FallsBackToEnforceAlways()
    {
        // Unit-test scenarios that don't run UseCanaryAuth get a null
        // accessor — the validator must default to the legacy 1.0.0
        // behavior (always enforce). Important for the 4 service-side test
        // projects (TenantService.Tests, etc.) that already assert the
        // rule fires.
        ReservedPrefixRuleExtensions.HttpContextAccessor = null;

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder("e2ec-a1b2c3d4-Test"));

        result.ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }

    [Fact]
    public void Validate_AccessorPresentButNoActiveRequest_FallsBackToEnforce()
    {
        // Background work / hosted services may resolve a validator without
        // an active HttpContext (accessor.HttpContext is null). The bypass
        // must NOT fire — defaulting to enforce keeps the security model
        // closed by default.
        ReservedPrefixRuleExtensions.HttpContextAccessor =
            new HttpContextAccessor(); // HttpContext is null

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder("e2ec-a1b2c3d4-Test"));

        result.ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }

    [Fact]
    public void Validate_CanaryBypass_StillAllowsNormalInput()
    {
        // Sanity check: in a canary request, non-prefixed input still
        // passes (the bypass only affects the prefix branch — it doesn't
        // disable validation altogether).
        StageHttpContextWithCanary(isCanary: true);

        var validator = new NullableValidator();
        validator.TestValidate(new StringHolder("MyTenant"))
            .ShouldNotHaveValidationErrorFor(x => x.Value);
        validator.TestValidate(new StringHolder(null))
            .ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    // ---------------------------------------------------------------------------
    // Bypass B (1.3.0): the authenticated user's identity name itself
    // matches the reserved prefix — i.e. the request was made by a canary
    // test user authenticating with a per-tenant JWT (no superUser role,
    // no canary header). This is the SPA-driven create flow.
    // ---------------------------------------------------------------------------

    [Theory]
    [InlineData("e2ec-849d3d47-e2e-tenanta-admin", "e2ec-849d3d47-Activation-Menu")]
    [InlineData("e2ec-deadbeef-e2e-tenantb-admin", "e2ec-deadbeef-Pizza Place")]
    [InlineData("e2ec-00000000-superuser", "e2ec-00000000-Quiz Template")]
    public void Validate_MatchingPrefix_WithCanaryUser_Bypassed(string username, string input)
    {
        // Production shape: SPA logged in as canary tenant admin POSTs to a
        // create endpoint with a canary-prefixed entity name. CanaryAuthMiddleware
        // has NOT tagged the request (no superUser role) but the username
        // itself carries the e2ec- prefix.
        StageHttpContextWithUser(username);

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(input));

        result.ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    [Theory]
    [InlineData("alice@example.com")]      // regular customer username
    [InlineData("admin-tenanta")]
    [InlineData("e2ec-foo")]                // doesn't match prefix regex
    [InlineData("E2EC-a1b2c3d4-Test")]      // uppercase — regex case-sensitive
    public void Validate_MatchingPrefix_WithRegularUser_StillFails(string username)
    {
        // Real customer: even though authenticated, their identity name
        // doesn't carry the canary prefix → both bypass branches stay
        // closed → the rule fires for any canary-prefixed input.
        StageHttpContextWithUser(username);

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder("e2ec-a1b2c3d4-Attempt"));

        result.ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }

    [Fact]
    public void Validate_AnonymousRequest_FallsBackToEnforce()
    {
        // No authenticated user → bypass B closed. The rule must still fire
        // on canary-prefixed input — important because the user-creation
        // path itself uses MustNotMatchReservedPrefix to keep customers from
        // self-provisioning e2ec- usernames in the first place.
        StageHttpContextWithUser(username: null);

        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder("e2ec-a1b2c3d4-Attempt"));

        result.ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }

    [Fact]
    public void Validate_CanaryUser_CustomPatternHonored()
    {
        // The username regex used for bypass B is the SAME regex configured
        // on the rule itself (so a service-specific ReservedPrefixPattern
        // stays in lockstep on both branches). With a custom pattern that
        // does NOT match the username, the bypass MUST not fire.
        StageHttpContextWithUser("e2ec-a1b2c3d4-canary-admin");
        var options = new CanaryOptions { ReservedPrefixPattern = @"^locked-" };

        var validator = new InlineValidator<StringHolder>();
        validator.RuleFor(x => x.Value).MustNotMatchReservedPrefix(options);

        // Input matches the custom pattern; username does NOT → enforce.
        validator.TestValidate(new StringHolder("locked-something"))
            .ShouldHaveValidationErrorFor(x => x.Value)
            .WithErrorCode(CanaryErrorCodes.ReservedPrefix);
    }
}
