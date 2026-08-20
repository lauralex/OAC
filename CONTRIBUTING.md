# Contributing to OAC

OAC accepts defensive engineering work that improves safety, correctness, compatibility,
observability, privacy, or test coverage. Contributions that add kernel exploitation, vulnerable
driver loading, security-control bypasses, hiding, or anti-forensics are out of scope.

Read `AGENTS.md` for repository invariants, `docs/README.md` for the public technical map, and
`docs/development/README.md` for progress, evidence, decisions, and roadmap records.

## Development setup

You need Visual Studio 2022 with the Desktop C++ workload, Windows SDK/WDK `10.0.26100.0`, and the
x64 toolchain. Build both supported configurations with the 64-bit MSBuild host:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe" `
  .\OAC.sln /m /t:Rebuild /p:Configuration=Debug /p:Platform=x64 `
  /nodeReuse:false /p:PreferredToolArchitecture=x64 /p:Inf2CatUseLocalTime=true

& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe" `
  .\OAC.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64 `
  /nodeReuse:false /p:PreferredToolArchitecture=x64 /p:Inf2CatUseLocalTime=true

& .\x64\Debug\OAC-Protocol-Unit.exe
& .\x64\Release\OAC-Protocol-Unit.exe

python -m pip install -r .\tools\requirements.txt
.\tools\Test-OACRepository.ps1
```

If Visual Studio is installed in another edition or location, use `vswhere.exe` as shown in
`AGENTS.md`.

## Change requirements

- Keep the driver demand-start and preserve all documented protocol and kernel safety checks.
- Update the driver, service, launcher or lab client, shared size assertions, pure unit tests,
  driver-backed protocol test, and docs together for an ABI change.
- Regenerate `shared/oac_driver_hash_policy.hpp` only with the pinned policy script. Review the
  archive hash, upstream policy version, rule count, and generated diff.
- Keep current behavior and planned behavior clearly labeled. A single VM result is not a universal
  Windows compatibility claim.
- Keep [`config/release-profile.json`](config/release-profile.json) synchronized with the INF,
  compatibility headers, SDK, and exact public/lab artifact boundary. Release outputs belong
  outside the repository.
- Do not include raw HWIDs, private reports, dumps, signing keys, binaries, or VM artifacts.

Run the checks appropriate to the change:

| Change | Required validation |
|---|---|
| Documentation or metadata | `tools/Test-OACRepository.ps1` and `git diff --check` |
| C/C++ or project files | Clean x64 Debug and Release rebuilds plus both pure unit executables |
| Driver, shared ABI, callbacks, or synchronization | PREfast, protocol tests, and Driver Verifier in a disposable VM |
| Client scanners | Clang-Tidy and an elevated VM smoke scan |
| INF, signing, or packaging | `InfVerif /w`, catalog/signature checks, and manifest verification |
| Release profile, artifacts, or symbols | Candidate creation/validation, five hostile mutations, SPDX schema validation, and public/private/lab allowlist review |
| Driver policy | Pinned regeneration and manual generated-diff review |

After a clean Release build, the local candidate checks are:

```powershell
$candidate = Join-Path $env:TEMP 'oac-candidate'

.\tools\New-OACReleaseCandidate.ps1 `
  -BuildDirectory .\x64\Release `
  -OutputDirectory $candidate

.\tools\Test-OACReleaseCandidate.ps1 `
  -BuildDirectory .\x64\Release `
  -CandidateDirectory $candidate
```

The public candidate is unsigned. Never add a production private key or broadly available signing
credential to a pull-request workflow. Follow [`docs/RELEASE.md`](docs/RELEASE.md) for the separate
certification, signing, symbol-retention, and promotion boundary.

Never enable test signing, disable Secure Boot, install the test driver, or run Driver Verifier on
a workstation you need to preserve. Follow `docs/test-signing.md` in an isolated disposable VM.

## Pull requests

Keep each pull request focused. Explain the threat or defect, the chosen behavior, compatibility and
privacy effects, and exactly which checks ran. Call out protocol, INF, driver lifecycle, signing,
or generated-policy changes explicitly. Security vulnerabilities should be reported privately as
described in `SECURITY.md`, not opened as public issues.
