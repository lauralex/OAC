# OAC hardening progress

**Status date:** 2026-08-19

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

WP-01 through WP-07 form the accepted production-control, target-lifetime, local-evidence, and
bounded-scheduling MVP. Acceptance commit `18aac02d291d9acfcb077fda67c17799a0382391`
passed the commit-bound disposable-VM and standard Driver Verifier campaign described below. Status
still distinguishes source, evidence, and the remaining production-hardening work packages.

| Work package | Status | Current evidence or next gate |
|---|---|---|
| WP-00 Baseline, docs, tests | Tested foundation | Baseline recorded; Debug/Release builds and units, repository validation, packaging, and the current VM campaign passed; PR #13 hosted checks passed |
| WP-01 Production protocol foundations | Tested foundation | Production ABI, explicit message types, validators, stable IDs, event schema, pure units, driver dispatch, and driver-backed protocol execution passed on the named campaign |
| WP-02 Service and device identity | VM-tested foundation | Restricted service, identity-checked launcher IPC, production device ACL, exact install/remove, standard-user status, and direct-open denials passed on the named campaign |
| WP-03 Per-file session state | VM-tested foundation | File/process/session identity, protocol exclusion, rundown, cleanup/close, generation, runtime race, live-target tombstone, and owner-exit cases passed on the named campaign |
| WP-04 Launch ticket and early binding | Working MVP; VM tested | One-use ticket, creation-time creator/path binding, suspended caller-token launch, exact process-handle confirmation, resume, hostile units, and Driver Verifier passed on the named campaign |
| WP-05 Job and liveness | Working MVP; VM tested | Service-owned kill-on-close job, pre-resume assignment, explicit idempotent revoke, session-loss latch, lease-state evaluator, and bounded crash/stop process-tree tests passed on the named campaign |
| WP-06 Alert/event/snapshot transport | Working MVP; VM tested | Separate retained-alert and overwrite-event queues, strict acknowledgement/cursor rules, persistent loss provenance, production loss revocation, service polling, and frozen paged kernel-module snapshots passed the named campaign |
| WP-07 Bounded service scheduler | Working MVP; VM tested | Independent health loop, one-slot worker queue, cancellation, incremental memory/thread sampling, fixed budgets, strict metrics, and shared resume guard passed the named campaign |
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
- `OAC/evidence.c`, `OAC/protection.c`, and `OAC/scanner.c`: callback-safe typed publication,
  independent retained-alert and overwrite-event queues, explicit loss accounting, and frozen
  paged kernel-module snapshots.
- `OAC-Service/`, `OAC-Launcher/`, `shared/oac_ipc.h`, and `shared/oac_lease.h`: restricted
  controller, identity-checked status IPC, one serialized caller-token launch transaction,
  service-owned target job, bounded alert polling/handoff, and a backend-independent lease-state
  policy seam. The service now keeps target inspection off the health loop, queues incremental
  memory/thread slices through one coalescing worker slot, and reports strict coverage and latency
  metrics to the launcher.
- Package/install and VM harness changes for the service boundary, production session lifecycle/race test, and
  Driver Verifier rerun.

The current driver advertises production session control, launch tickets, session liveness, typed
evidence, and paged snapshots. Production configuration/scan, signed-manifest, signed-policy, and
backend capabilities remain unavailable.

## Current local validation

| Check | Result |
|---|---|
| `Debug|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| `Release|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| Current Debug and Release `OAC-Protocol-Unit.exe` | Passed; `428/428` in each configuration, including scheduler budgets, metrics, and thread-resume cleanup |
| Release driver PREfast with `DriverMinimumRules` | Passed; zero reported warnings and errors |
| Solution-wide Release C/C++ analysis | Passed; zero reported warnings and errors |
| Release Clang-Tidy for the service and diagnostic scanner projects | Passed with warnings treated as errors |
| `InfVerif /w OAC/OAC.inf` and WDK `Inf2Cat` | Passed; zero warnings and errors |
| `tools/Test-OACRepository.ps1` (seven PowerShell, eleven XML, five YAML, one Python) | Passed |
| Markdown local-link resolution across the repository | Passed |
| Parse all five `.github` YAML files with PyYAML | Passed |
| `git diff --check` across the shared working tree | Passed |

`actionlint` and PSScriptAnalyzer are not installed on this workstation. The current CI workflow
does not yet provide CodeQL or SBOM-generation evidence. These are explicit remaining CI and
static-analysis gaps rather than implied passes.

## Current disposable-VM validation

Acceptance commit `18aac02d291d9acfcb077fda67c17799a0382391` passed on Microsoft Windows
11 Pro 10.0.26100 build 26100 in a networkless Generation 2 Hyper-V VM with test signing enabled
and Secure Boot disabled. The host accepted 30 exact result records, including five protocol
executions and thirteen client, launcher, and preflight executions. The campaign passed production
service identity and direct-open boundaries, two standard-user suspended launches with
creation-time binding, exact-handle confirmation, verified job assignment, and first-thread resume.
It also proved service-crash and graceful-stop termination of both target and child, SCM recovery,
idempotent explicit revoke, and monotonic session-loss transitions from sequence `0` to `1` to `2`
with reasons `none`, `service exit`, and `requested shutdown`.

The restricted service completed all 35 queued scan slices and seven full memory/thread sweeps with
no coalesced, cancelled, or failed slice. It inspected 1,253 memory regions and 21 threads; the
maximum measured health-loop delay was 297 ms, scan-slice duration 90.479 ms, and thread suspension
33.059 ms, all within the campaign bounds. Exact remove/reinstall, per-file cleanup and tombstone
races, the armed renamed-driver load gate, kernel provenance, and standard Driver Verifier passed.
Final Verifier flags were clear, both OAC services were stopped, the VM was Off with zero adapters,
and there were zero crash events and zero minidumps. The driver-free unit suite passed `428/428`;
each of four driver-backed protocol executions passed `129/129`. Driver Verifier recorded three OAC
loads and three unloads. The validated result ZIP SHA-256 was
`D87B84BB0B3CAF2664474CC15B1DD2889152D83C0D7999D72ADF05DB8C6CC4C7`.

Compact evidence is retained at `C:\OAC-VM\evidence\20260819-18aac02`. The exact VM, checkpoint,
VHD/AVHDX, package, seed, and campaign directory were deleted after validation. Under `C:\OAC-VM`,
only the verified Windows installation ISO and two compact evidence bundles remain.

## Current pending gates

- Hosted Debug/Release build, unit, and repository-validation checks passed on PR #13 and remain
  required for each merge.
- WP-08 must add centralized typed policy before the hardened-foundation definition is met.
- The Windows 10/11/Server, HVCI/VBS, hardware, and game-compatibility matrix remains incomplete.

No milestone is described as production-ready or as a complete hardened foundation. The control
plane still lacks centralized policy, signed manifests, and authenticated backend delivery listed
above.
