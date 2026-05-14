using Canary.AspNetCore.Context;
using Shouldly;

namespace Canary.AspNetCore.Tests.Context;

public sealed class CanaryRunContextTests
{
    [Fact]
    public void Default_IsCanary_IsFalse_AndIdsAreNull()
    {
        var context = new CanaryRunContext();

        context.IsCanary.ShouldBeFalse();
        context.RunId.ShouldBeNull();
        context.RunIdShort.ShouldBeNull();
    }

    [Fact]
    public void Activate_FullUuid_SetsRunIdAndComputesShortKey()
    {
        var context = new CanaryRunContext();

        context.Activate("a1b2c3d4-1234-5678-9abc-def012345678");

        context.IsCanary.ShouldBeTrue();
        context.RunId.ShouldBe("a1b2c3d4-1234-5678-9abc-def012345678");
        context.RunIdShort.ShouldBe("a1b2c3d4");
    }

    [Fact]
    public void Activate_ShortString_ShortKeyClampsToInput()
    {
        // Defensive - middleware always passes a UUID but the helper should not
        // throw on short inputs (it just returns the full value as the short
        // key). The middleware-level Guid.TryParse is the real format guard.
        var context = new CanaryRunContext();

        context.Activate("abc");

        context.IsCanary.ShouldBeTrue();
        context.RunIdShort.ShouldBe("abc");
    }

    [Fact]
    public void Activate_EmptyString_Throws()
    {
        var context = new CanaryRunContext();

        Should.Throw<ArgumentException>(() => context.Activate(string.Empty));
    }
}
