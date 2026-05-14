# Canary.AspNetCore

Cross-cutting middleware + validation primitives for the E2E **canary protocol**
— the mechanism that lets a Playwright run exercise a live deployment without
its data colliding with real customer data or hitting real third-party APIs.

Shared NuGet package consumed by every backend service in the stack
(IdentityService, PaymentService, NotificationService, OnlineMenuService,
QuestionerService, ContentService).

## What it does

1. **Gates the `X-Canary-Run-Id` header** on a valid `superUser` JWT. The header
   alone does nothing — without the role it gets HTTP 403 `INVALID_CANARY_AUTH`.
   With the role, the request is tagged for downstream behavioral mocks
   (PaymentService skips Stripe, NotificationService suppresses SMTP/SMS).
2. **Rejects reserved-prefix names** at the validator layer. Any user-controlled
   name field that the cleanup endpoint sweeps by prefix (`e2ec-{runId8}-*`)
   must refuse matching input so real customer data cannot collide with the
   canary sweep.
3. **Provides a per-request canary accessor** (`ICanaryRunContext`) that
   endpoints inject when they need to branch on canary state.

## Install

```xml
<PackageReference Include="Canary.AspNetCore" Version="1.0.0" />
```

## Public API surface

| Type | Purpose |
|------|---------|
| `AddCanaryAuth(IConfiguration, Action<CanaryOptions>?)` | DI registration — binds `CanaryOptions` + registers the scoped `ICanaryRunContext`. |
| `UseCanaryAuth()` | Pipeline registration — adds `CanaryAuthMiddleware`. **Must run after `UseAuthorization()`.** |
| `ICanaryRunContext` | Scoped per-request accessor: `IsCanary`, `RunId`, `RunIdShort`. Inject this into endpoints. |
| `CanaryRunContext` | Concrete implementation of `ICanaryRunContext`. Public so middleware-level tests can construct it without `InternalsVisibleTo`; endpoints should still depend on the interface. |
| `CanaryAuthMiddleware` | The header-gating middleware. Registered via `UseCanaryAuth()`. |
| `CanaryOptions` | Bound to the `Canary` config section — `HeaderName`, `RequiredRole`, `ReservedPrefixPattern`. All have sensible defaults. |
| `CanaryErrorCodes` | Stable error-code constants: `RESERVED_PREFIX`, `INVALID_CANARY_AUTH`, `INVALID_CANARY_RUN_ID`. |
| `MustNotMatchReservedPrefix<T, TProperty>(CanaryOptions?)` | FluentValidation rule extension — rejects reserved-prefix input with code `RESERVED_PREFIX`. |

## Pipeline placement (CRITICAL)

`UseCanaryAuth()` MUST be registered **after** `UseAuthorization()`. Registering
it earlier would let unauthenticated callers probe canary behavior via
response-timing differences. The class-level remarks on `CanaryAuthMiddleware`
document this in detail.

```csharp
app.UseAuthentication();
app.UseAuthorization();
app.UseCanaryAuth();   // <- AFTER authorization
app.UseRateLimiter();
app.UseFastEndpoints(...);
```

## Consumer-side registration

```csharp
// Program.cs (or ProgramExtensions.cs)
builder.Services.AddCanaryAuth(builder.Configuration);

// ... app build ...

app.UseAuthentication();
app.UseAuthorization();
app.UseCanaryAuth();
```

## Reserved-prefix validation

Add to every FluentValidation validator rule that names user-controlled fields
the cleanup endpoint sweeps:

```csharp
using Canary.AspNetCore.Validation;

public class CreateMenuRequestValidator : Validator<CreateMenuRequest>
{
    public CreateMenuRequestValidator()
    {
        RuleFor(x => x.Name)
            .NotEmpty()
            .MaximumLength(100)
            .MustNotMatchReservedPrefix();   // <- adds RESERVED_PREFIX rule
    }
}
```

Failing input produces a 400 with error code `RESERVED_PREFIX`.

## Endpoint-side usage of the canary context

```csharp
public class CreateSubscription(ICanaryRunContext canary) : Endpoint<...>
{
    public override async Task HandleAsync(...)
    {
        if (canary.IsCanary)
        {
            // Skip Stripe; write a mock subscription tagged with canary.RunIdShort
        }
        else
        {
            // Normal Stripe flow
        }
    }
}
```

## Configuration

The `Canary` section binds to `CanaryOptions`. All settings have sensible
defaults; only override when the service has a genuinely different protocol.

```jsonc
{
  "Canary": {
    "HeaderName": "X-Canary-Run-Id",
    "RequiredRole": "superUser",
    "ReservedPrefixPattern": "^e2ec-[0-9a-f]{8}-"
  }
}
```

## Observability

When canary mode activates, the middleware:
- Pushes a Serilog `LogContext` property `canary_run_id` for the duration of
  the request — all downstream log lines carry the property automatically.
- Echoes the `X-Canary-Run-Id` header back on the response so the E2E runner
  can confirm its header was honored.

Prometheus labeling lives outside this library (the service-level metrics
middleware in `Metrics.Client` reads `ICanaryRunContext` at scrape time).

## Cleanup endpoint pattern (per-service)

This library does **not** ship the cleanup endpoint — each service owns its own
because the entities differ. The recommended shape:

```
DELETE /api/v1/internal/canary-cleanup?runId={uuid}
Authorization: Bearer <superUser JWT>
Response: { "usersDeleted": N, "tenantsDeleted": M, ... }
```

Cleanup endpoints MUST:
- Require the `superUser` role.
- Validate `runId` is a UUID (regex `^[0-9a-f-]{36}$`) to refuse arbitrary
  prefixes being interpreted as `LIKE` patterns.
- Be idempotent — re-runs return 0 counts, not 404.
- Delete by the `e2ec-{runId8}-` name prefix where `runId8` is the first 8
  hex chars of the supplied UUID.

## License

MIT
