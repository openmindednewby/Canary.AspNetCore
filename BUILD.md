# Building and Publishing Canary.AspNetCore

## Prerequisites

- .NET 10 SDK
- nuget.org API key with push permissions for `Canary.AspNetCore*`

## Build

```bash
dotnet restore Canary.AspNetCore.sln
dotnet build Canary.AspNetCore.sln -c Release --no-restore
dotnet pack src/Canary.AspNetCore/Canary.AspNetCore.csproj -c Release -o artifacts --no-build
```

## Test

```bash
dotnet test tests/Canary.AspNetCore.Tests/Canary.AspNetCore.Tests.csproj -c Release
```

The test project covers the library directly — `CanaryRunContext`,
`CanaryAuthMiddleware`, and the `MustNotMatchReservedPrefix` validator rule.
Per-service test suites only cover their own canary integration (cleanup
endpoints, behavioral mock handlers).

## Publish

```powershell
.\publish.ps1 -Bump patch -ApiKey YOUR_KEY
```

The script auto-bumps the version in `Directory.Build.props`, builds, packs,
pushes, and rolls back on failure.

## Versioning

Semantic versioning: `patch` for bug fixes, `minor` for new features, `major`
for breaking changes.

## Release Checklist

- [ ] Update `Directory.Build.props` version (handled by publish.ps1)
- [ ] Run `dotnet build -c Release`
- [ ] Run `dotnet test`
- [ ] Run `.\publish.ps1`
- [ ] Wait 5–15 min for nuget.org indexing
- [ ] Verify on https://www.nuget.org/packages/Canary.AspNetCore
- [ ] Bump consumers' `Directory.Packages.props` references

## InternalsVisibleTo decision

This package ships **no `InternalsVisibleTo`**. The original 6 in-tree copies
each had a hardcoded `InternalsVisibleTo` for their service's test project
because `CanaryRunContext` and its `Activate()` method were `internal`. A
published NuGet cannot enumerate 6 different consumers' test projects, so
`CanaryRunContext` and `Activate()` were promoted to `public`. Endpoints still
inject the read-only `ICanaryRunContext` interface — the concrete class being
public only widens what middleware-level tests can construct, not the contract
consumers depend on.
