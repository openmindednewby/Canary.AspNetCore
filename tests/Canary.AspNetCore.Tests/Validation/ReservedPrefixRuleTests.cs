using Canary.AspNetCore.Configuration;
using Canary.AspNetCore.Validation;
using FluentValidation;
using FluentValidation.TestHelper;
using Shouldly;

namespace Canary.AspNetCore.Tests.Validation;

public sealed class ReservedPrefixRuleTests
{
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
        var validator = new NullableValidator();
        var result = validator.TestValidate(new StringHolder(input));

        result.ShouldNotHaveValidationErrorFor(x => x.Value);
    }

    [Fact]
    public void Validate_NullValue_Passes()
    {
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
}
