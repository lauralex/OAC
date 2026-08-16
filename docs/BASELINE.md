# OAC baseline

**Status:** Tested build baseline and inspected implementation snapshot

**Recorded:** 2026-08-16

**Current snapshot:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed implementation baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

This document freezes the starting point for the production-hardening work. It is evidence about
the named revisions, not a claim that later work packages are complete.

> [!NOTE]
> The current working tree now contains the protocol-v5, restricted-service, and per-file session
> foundations described in `ARCHITECTURE.md` and `PROTOCOL.md`. The statements below intentionally
> remain frozen at `075ad21`; they are not a description of current source. Current disposable-VM
> acceptance for WP-02 and WP-03 is pending.

## Revision delta

The current snapshot differs from the reviewed implementation baseline only in repository
scaffolding, documentation, and GitHub workflow metadata. The delta does not change files under
`OAC/`, `OAC-Client/`, `shared/`, or `tools/`. The source behavior reviewed at `90dfdfa` therefore
remains the implementation baseline at `075ad21`.

## Implemented at the baseline

- An unsigned-by-default, demand-start x64 WDM driver built as C17.
- A directly elevated C++20 client that claims the driver and retains client and target identities
  as referenced process objects.
- Protocol v4 (`0x00040000`) with fixed-size, C-compatible, buffered request and response layouts.
- Object callbacks for user-mode process and thread handle filtering.
- Bounded kernel scans, CPU snapshots, load-image telemetry, and a monotonic post-start driver-load
  latch.
- User-mode system, target, platform, driver-policy, and privacy-preserving hardware-identity
  collection.
- A 23-check driver-backed protocol integration test and a disposable Hyper-V/Driver Verifier
  harness.

The baseline does not contain a dedicated service, restricted service IPC, per-file-object
sessions, launch tickets, signed game manifests or policy, backend leases, protocol v5, or split
alert/event/snapshot channels.

## Toolchain observed

| Item | Observed value |
|---|---|
| Development host | Windows 11 Enterprise x64, build 22631 |
| Visual Studio | Enterprise 2022, 17.14.35 |
| MSBuild | 17.14.40.60911, x64 host |
| MSVC | 19.44.35228; toolset directory 14.44.35207 |
| Project SDK/WDK | 10.0.26100.0 |
| Configurations | `Debug|x64`, `Release|x64` |

The projects enable `/W4`, warnings as errors, SDL checks, buffer security checks, and CFG. Release
builds enable Spectre mitigation; the driver links with `/INTEGRITYCHECK`. Driver signing remains
off in the checked-in projects.

## Build evidence

The following baseline command completed locally for `Release|x64`:

```powershell
$oacVswhere = Join-Path ${env:ProgramFiles(x86)} `
  'Microsoft Visual Studio\Installer\vswhere.exe'
$oacVs = & $oacVswhere -latest -products * `
  -requires Microsoft.Component.MSBuild -property installationPath
$oacMsbuild = Join-Path $oacVs 'MSBuild\Current\Bin\amd64\MSBuild.exe'

& $oacMsbuild .\OAC.sln /m /t:Rebuild `
  /p:Configuration=Release /p:Platform=x64 `
  /p:PreferredToolArchitecture=x64 /p:Inf2CatUseLocalTime=true
```

Result: **passed**. This command built the driver, client, and protocol-test projects and produced
an unsigned driver package. It did not install or load the driver.

The last pre-hardening `main` workflow run inspected was
[GitHub Actions run 31939833917](https://github.com/lauralex/OAC/actions/runs/31939833917)
at `075ad21`. It completed the unsigned `Release|x64` build with zero warnings and zero errors.
That workflow did not execute tests and did not build Debug.

## Test evidence boundary

**Tested in this baseline run:** the local Release build and non-mutating repository/schema checks.

**Historically tested:** `README.md` records a networkless Windows 11 Pro 24H2 build 26100 campaign
with four protocol-test executions, seven client gates, a renamed signed driver-load probe, and
standard Driver Verifier. The raw campaign output is not tracked, and that VM campaign was not
rerun for this baseline. Treat it as historical evidence for that exact environment only.

**Not tested by this baseline:** Debug runtime behavior, HVCI/VBS variants, Windows 10 or Server,
service/session behavior, concurrency and cleanup races, protocol v5, or production signing.

## Baseline risks carried forward

- The first eligible administrator process can claim global driver authority.
- Device exclusivity can deny the intended client.
- Target binding occurs after process creation.
- `IRP_MJ_CREATE`, `IRP_MJ_CLEANUP`, and `IRP_MJ_CLOSE` do not maintain session state.
- The single 512-record ring can overwrite unacknowledged critical evidence.
- Expensive scans block the monitor loop.
- Policy is partly duplicated and human-readable text can affect classification.
- Kernel sequence and time provenance are replaced in the user-mode report.
- There is no authenticated component, policy, launch, evidence-upload, or backend-lease path.

See `SECURITY_MODEL.md`, `ARCHITECTURE.md`, `PROTOCOL.md`, and `TEST_MATRIX.md` for the corresponding
boundaries and planned acceptance evidence.
