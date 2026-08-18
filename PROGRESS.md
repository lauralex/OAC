# OAC hardening progress

**Status date:** 2026-08-18

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

WP-01 through WP-04 form the accepted production-control MVP. Implementation commit
`bbf8f06bd9383be2d9de079a95b67d87848c280c` passed the commit-bound disposable-VM and standard
Driver Verifier campaign described below. WP-05 job and liveness controls are now implemented in
the current source; their one fresh disposable-VM acceptance campaign remains pending. Status still
distinguishes source, evidence, and the remaining production-hardening work packages.

| Work package | Status | Current evidence or next gate |
|---|---|---|
| WP-00 Baseline, docs, tests | Tested foundation | Baseline recorded; Debug/Release builds and units, repository validation, packaging, and the current VM campaign passed; PR #8 hosted checks passed before merge |
| WP-01 Production protocol foundations | Tested foundation | Production ABI, explicit message types, validators, stable IDs, event schema, pure units, driver dispatch, and driver-backed protocol execution passed on the named campaign |
| WP-02 Service and device identity | VM-tested foundation | Restricted service, identity-checked launcher IPC, production device ACL, exact install/remove, standard-user status, and direct-open denials passed on the named campaign |
| WP-03 Per-file session state | VM-tested foundation | File/process/session identity, protocol exclusion, rundown, cleanup/close, generation, runtime race, live-target tombstone, and owner-exit cases passed on the named campaign |
| WP-04 Launch ticket and early binding | Working MVP; VM tested | One-use ticket, creation-time creator/path binding, suspended caller-token launch, exact process-handle confirmation, resume, hostile units, and Driver Verifier passed on the named campaign |
| WP-05 Job and liveness | Source present; VM pending | Service-owned kill-on-close job, pre-resume assignment, explicit idempotent revoke, session-loss latch, lease-state evaluator, and bounded crash/stop tests are implemented; final VM/Verifier acceptance is pending |
| WP-06 Alert/event/snapshot transport | Planned | Typed event schema exists; no production event transport is advertised or dispatched |
| WP-07 Bounded service scheduler | Planned | No independent health loop or bounded worker scheduler exists |
| WP-08 Rule catalog and policy engine | Planned | Stable IDs exist; no central production policy evaluator |
| WP-09 Signed game manifest | Planned | No manifest verifier or key scope |
| WP-10 Signed policy/update model | Planned | Existing vulnerable-driver hash snapshot is not the planned signed policy channel |
| WP-11 Backend session abstraction | Planned | No backend lease, authenticated upload, or replay service |
| WP-12 Scanner modularization | Planned | Refactor behind tests; preserve lab behavior |
| WP-13 Game/server integration | Planned | No current game-specific server detector |
| WP-14 Production release engineering | Planned | Signing/HLK, SBOM, updates, privacy, and operations remain prerequisites |

These tested states apply only to the named commit and Windows build; they are not general platform
certification or production readiness.

## Frozen WP-00 evidence

The frozen baseline established the documentation and validation boundary before source hardening.
It added:

- `docs/BASELINE.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_MODEL.md`
- `docs/PROTOCOL.md`
- `docs/TEST_MATRIX.md`
- `docs/README.md`
- `PROGRESS.md`
- `DECISIONS.md`
- the Debug/Release unit-test workflow design

| Command or inspection | Frozen-baseline result |
|---|---|
| `git rev-parse HEAD` | `075ad2109f84cce90727f8ba65f87b807500e6b7` |
| `git diff --name-status 90dfdfa..075ad21` | Scaffolding, documentation, and workflow metadata only |
| Local `Release|x64` solution rebuild | Passed; driver not installed or loaded |
| Prior `main` Actions run inspection | Release build passed with zero warnings/errors; no tests ran |
| PowerShell 7 and Windows PowerShell AST parse | Passed for the then-checked-in scripts |
| XML/project/filter parsing | Passed |
| Python source compilation | Passed |
| GitHub YAML parse | Passed locally with available PyYAML |
| Markdown local-link check | Passed |
| `InfVerif /w OAC/OAC.inf` | Passed |
| Disposable VM runtime suite | Not rerun; README evidence remained historical |

These results do not validate the current production protocol, service, or session changes.

## Current foundation source

The working tree adds or changes these implementation areas:

- `shared/protocol/oac_v5.h` and `shared/protocol/oac_validate.h`: C-compatible production ABI, explicit
  message identities, layout assertions, strict request/response/event validation, and transition
  rules.
- `tests/unit/`: driver-free C/C++ validation of layouts, hostile inputs, correlation, state
  transitions, and event provenance/payloads.
- `OAC/session.c` and `OAC/session.h`: per-file contexts, service/process identity, random session
  and launch IDs, generations, one-use launch state, creation-time target binding, rundown,
  cleanup/close, and target tombstones.
- `OAC/main.c`: production negotiate/claim/status/revoke and launch-ticket dispatch, plus lab-only
  diagnostic authorization.
- `OAC-Service/`, `OAC-Launcher/`, `shared/oac_ipc.h`, and `shared/oac_lease.h`: restricted
  controller, identity-checked status IPC, one serialized caller-token launch transaction,
  service-owned target job, and a backend-independent lease-state policy seam.
- Package/install and VM harness changes for the service boundary, production session lifecycle/race test, and
  Driver Verifier rerun.

The current driver advertises production session control, launch tickets, and session liveness.
Scan, event, CPU, signed-manifest, signed-policy, and backend capabilities remain unavailable.

## Current local validation

| Check | Result |
|---|---|
| `Debug|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| `Release|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| Current Debug and Release `OAC-Protocol-Unit.exe` | Passed; `314/314` in each configuration after the WP-05 implementation |
| Release driver PREfast with `DriverMinimumRules` | Passed; zero reported warnings and errors |
| Solution-wide Release C/C++ analysis | Passed; zero reported warnings and errors |
| `InfVerif /w OAC/OAC.inf` and WDK `Inf2Cat` | Passed; zero warnings and errors |
| `tools/Test-OACRepository.ps1` (seven PowerShell, eleven XML, five YAML, one Python) | Passed |
| Markdown local-link resolution across the repository | Passed |
| Parse all five `.github` YAML files with PyYAML | Passed |
| `git diff --check` across the shared working tree | Passed |

`actionlint`, Clang-Tidy, and PSScriptAnalyzer are not installed on this workstation. The current
CI workflow does not yet provide CodeQL, SBOM generation, or secret-scanning evidence. These are
explicit remaining CI/static-analysis gaps rather than implied passes.

## Current disposable-VM validation

Implementation commit `bbf8f06bd9383be2d9de079a95b67d87848c280c` passed on Microsoft Windows
11 Pro 10.0.26100 build 26100 in a networkless Generation 2 Hyper-V VM with test signing enabled
and Secure Boot disabled. The host accepted 27 exact result records, including five protocol
executions and ten client, launcher, and preflight executions. The campaign passed production
service identity and direct-open boundaries, one standard-user suspended launch with creation-time
binding and exact-handle confirmation, exact remove/reinstall, per-file cleanup and tombstone races,
the armed renamed-driver load gate, kernel provenance, and standard Driver Verifier. Verifier
recorded three loads and three unloads of `OAC.sys`; final Verifier flags were clear, both OAC
services were stopped, the VM was Off with zero adapters, and there were zero crash events and zero
minidumps. The validated result ZIP SHA-256 was
`46BE5BF86FB46AA1839864DE4A0240840EDED0095CA70A7FFBE49BF8E8A8EC64`.

Compact evidence is retained at `C:\OAC-VM\evidence\20260817-bbf8f06`. Large disposable artifacts
were deleted after validation.

## Current pending gates

- Hosted Debug/Release build, unit, and repository-validation checks passed on PR #8 and remain
  required for each merge.
- WP-05 requires one commit-bound disposable-VM/Verifier acceptance run for the implemented
  crash, graceful-stop, child-process, explicit-revoke, and recovery paths.
- WP-06 through WP-08 must add production evidence transport, bounded scheduling, and centralized
  typed policy before the hardened-foundation definition is met.
- The Windows 10/11/Server, HVCI/VBS, hardware, and game-compatibility matrix remains incomplete.

No milestone is described as production-ready or as a complete hardened foundation. The minimal
control plane still lacks production telemetry, policy, signed manifest, and backend work listed
above.
