using System.Security.Claims;
using System.Text;
using Canary.AspNetCore.Configuration;
using Canary.AspNetCore.Context;
using Canary.AspNetCore.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;

namespace Canary.AspNetCore.Tests.Middleware;

/// <summary>
/// Contract tests for <see cref="CanaryAuthMiddleware"/>. The four cases
/// below are the security gating spec from
/// <c>e2e-multi-environment-execution.md</c> — the canary header must do
/// NOTHING without a valid superUser JWT, and the middleware itself must
/// run AFTER authorization so <see cref="HttpContext.User"/> is populated.
/// </summary>
/// <remarks>
/// These tests fake out the auth pipeline by setting
/// <c>HttpContext.User</c> directly. Integration with the real
/// <c>UseAuthentication</c>/<c>UseAuthorization</c> chain is verified
/// implicitly by the production wiring in <c>ProgramExtensions.cs</c>
/// (the middleware ordering there is the part this test cannot exercise
/// in isolation).
/// </remarks>
public sealed class CanaryAuthMiddlewareTests
{
    private const string ValidRunId = "a1b2c3d4-1234-5678-9abc-def012345678";
    private const string HeaderName = "X-Canary-Run-Id";

    // ---------------------------------------------------------------------------
    // Security gating - the 4 cases the design's "Security review checklist"
    // calls out as non-negotiable.
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task Invoke_HeaderPresent_SuperUserRole_TagsRequestAndContinues()
    {
        // Header + valid superUser JWT - the only path that should activate canary
        // mode. The middleware sets the context, echoes the header back, and calls
        // the next delegate.
        var context = BuildContext(headerValue: ValidRunId, role: "superUser");
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeTrue();
        context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
        canaryContext.IsCanary.ShouldBeTrue();
        canaryContext.RunId.ShouldBe(ValidRunId);
        canaryContext.RunIdShort.ShouldBe("a1b2c3d4");
        context.Response.Headers["X-Canary-Run-Id"].ToString().ShouldBe(ValidRunId);
    }

    [Fact]
    public async Task Invoke_HeaderPresent_NoAuth_Returns403_AndDoesNotCallNext()
    {
        // Unauthenticated caller sending the header - explicitly forbidden by the
        // design. 403 (not 401) so the response shape is consistent regardless
        // of why the role check failed.
        var context = BuildContext(headerValue: ValidRunId, role: null);
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeFalse();
        context.Response.StatusCode.ShouldBe(StatusCodes.Status403Forbidden);
        canaryContext.IsCanary.ShouldBeFalse();
        canaryContext.RunId.ShouldBeNull();
        ReadResponseBody(context).ShouldContain(CanaryErrorCodes.InvalidCanaryAuth);
    }

    [Fact]
    public async Task Invoke_HeaderPresent_NonAdminRole_Returns403_AndDoesNotCallNext()
    {
        // Authenticated but lacking the superUser role - the privilege-escalation
        // path the design explicitly closes. The error code is the same as the
        // anonymous-caller path so the response shape doesn't leak whether the
        // problem was auth or role.
        var context = BuildContext(headerValue: ValidRunId, role: "user");
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeFalse();
        context.Response.StatusCode.ShouldBe(StatusCodes.Status403Forbidden);
        canaryContext.IsCanary.ShouldBeFalse();
        ReadResponseBody(context).ShouldContain(CanaryErrorCodes.InvalidCanaryAuth);
    }

    [Fact]
    public async Task Invoke_NoHeader_FlowsThroughUntagged_RegardlessOfAuth()
    {
        // Default path - no canary header means no canary tagging, regardless
        // of whether the caller is anonymous, a user, or a superUser. This is
        // the "behave normally" case.
        var context = BuildContext(headerValue: null, role: "superUser");
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeTrue();
        canaryContext.IsCanary.ShouldBeFalse();
        canaryContext.RunId.ShouldBeNull();
        context.Response.Headers.ContainsKey("X-Canary-Run-Id").ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------
    // Header format - belt-and-suspenders next to the role gate.
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task Invoke_HeaderMalformed_Returns400_AndDoesNotCallNext()
    {
        var context = BuildContext(headerValue: "not-a-uuid", role: "superUser");
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeFalse();
        context.Response.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        ReadResponseBody(context).ShouldContain(CanaryErrorCodes.InvalidRunId);
        canaryContext.IsCanary.ShouldBeFalse();
    }

    [Fact]
    public async Task Invoke_HeaderEmpty_TreatedAsAbsent_FlowsThrough()
    {
        var context = BuildContext(headerValue: string.Empty, role: "superUser");
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeTrue();
        canaryContext.IsCanary.ShouldBeFalse();
    }

    [Fact]
    public async Task Invoke_HeaderWhitespaceOnly_TreatedAsAbsent_FlowsThrough()
    {
        var context = BuildContext(headerValue: "   ", role: "superUser");
        var nextWasCalled = false;
        var canaryContext = new CanaryRunContext();
        var middleware = BuildMiddleware(_ =>
        {
            nextWasCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, canaryContext);

        nextWasCalled.ShouldBeTrue();
        canaryContext.IsCanary.ShouldBeFalse();
    }

    [Fact]
    public async Task Invoke_CustomRequiredRole_RejectsSuperUserToken_AcceptsConfiguredRole()
    {
        // Sanity: the role name is configurable via CanaryOptions.RequiredRole.
        // Slice 2-6 services that want a different role should change the
        // config, not edit the middleware.
        var options = new CanaryOptions { RequiredRole = "canary-runner" };

        var contextWithCustomRole = BuildContext(headerValue: ValidRunId, role: "canary-runner");
        var contextWithSuperUserOnly = BuildContext(headerValue: ValidRunId, role: "superUser");

        var canaryA = new CanaryRunContext();
        var canaryB = new CanaryRunContext();
        var middleware = BuildMiddleware(_ => Task.CompletedTask, options);

        await middleware.InvokeAsync(contextWithCustomRole, canaryA);
        await middleware.InvokeAsync(contextWithSuperUserOnly, canaryB);

        canaryA.IsCanary.ShouldBeTrue();
        canaryB.IsCanary.ShouldBeFalse();
        contextWithSuperUserOnly.Response.StatusCode.ShouldBe(StatusCodes.Status403Forbidden);
    }

    // ---------------------------------------------------------------------------
    // Builders.
    // ---------------------------------------------------------------------------

    private static CanaryAuthMiddleware BuildMiddleware(
        RequestDelegate next,
        CanaryOptions? options = null)
    {
        return new CanaryAuthMiddleware(
            next,
            Options.Create(options ?? new CanaryOptions()),
            NullLogger<CanaryAuthMiddleware>.Instance);
    }

    private static HttpContext BuildContext(string? headerValue, string? role)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();

        if (headerValue is not null)
        {
            ctx.Request.Headers[HeaderName] = headerValue;
        }

        if (role is not null)
        {
            // Mimic what JwtBearerEvents.OnTokenValidated does in production -
            // a ClaimsIdentity with the configured RoleClaimType. The middleware
            // calls User.IsInRole(...) which honors ClaimsIdentity.RoleClaimType.
            var identity = new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Role, role) },
                authenticationType: "Test",
                nameType: ClaimsIdentity.DefaultNameClaimType,
                roleType: ClaimTypes.Role);
            ctx.User = new ClaimsPrincipal(identity);
        }

        return ctx;
    }

    private static string ReadResponseBody(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        using var reader = new StreamReader(ctx.Response.Body, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
