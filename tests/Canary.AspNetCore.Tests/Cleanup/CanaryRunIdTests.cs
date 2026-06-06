using Canary.AspNetCore.Cleanup;
using Shouldly;

namespace Canary.AspNetCore.Tests.Cleanup;

public sealed class CanaryRunIdTests
{
    private const string ValidUuid = "a1b2c3d4-1234-5678-9abc-def012345678";

    [Theory]
    [InlineData("a1b2c3d4-1234-5678-9abc-def012345678")]
    [InlineData("A1B2C3D4-1234-5678-9ABC-DEF012345678")]
    public void IsValid_AcceptsWellFormedUuids(string runId)
    {
        CanaryRunId.IsValid(runId).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-uuid")]
    [InlineData("a1b2c3d4")]
    [InlineData("a1b2c3d4-1234-5678-9abc-def012345678'; DROP TABLE")]
    [InlineData("g1b2c3d4-1234-5678-9abc-def012345678")] // non-hex
    public void IsValid_RejectsMalformed(string? runId)
    {
        CanaryRunId.IsValid(runId).ShouldBeFalse();
    }

    [Fact]
    public void ToShort_ReturnsFirstEightChars()
    {
        CanaryRunId.ToShort(ValidUuid).ShouldBe("a1b2c3d4");
    }

    [Fact]
    public void ToShort_ThrowsOnMalformedUuid()
    {
        Should.Throw<ArgumentException>(() => CanaryRunId.ToShort("not-a-uuid"));
    }

    [Fact]
    public void TryToShort_ValidUuid_ReturnsTrueAndShortKey()
    {
        CanaryRunId.TryToShort(ValidUuid, out var runIdShort).ShouldBeTrue();
        runIdShort.ShouldBe("a1b2c3d4");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-uuid")]
    public void TryToShort_Malformed_ReturnsFalseAndNull(string? runId)
    {
        CanaryRunId.TryToShort(runId, out var runIdShort).ShouldBeFalse();
        runIdShort.ShouldBeNull();
    }

    [Fact]
    public void RoleRequired_IsSuperUser()
    {
        CanaryRunId.RoleRequired.ShouldBe("superUser");
    }
}
