# OAC hardening progress

**Status date:** 2026-08-19

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

WP-01 through WP-08 form the accepted production-control, target-lifetime, local-evidence,
bounded-scheduling, and local-policy MVP. Acceptance commit
`5c476c246462c968d98185c6db159fdaf6a0238d`
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
| WP-08 Rule catalog and policy engine | Working MVP; VM tested | Fixed catalog, five-level confidence, seven actions, three deployment modes, typed signer state, service enforcement, display-text independence, and integrated VM/Verifier execution passed on the named campaign |
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

The current source is organized around these implementation areas:

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
- `shared/oac_policy.h` and `shared/oac_policy.c`: C-compatible stable catalog, Observe/Enforce/Strict
  decisions, five-level policy confidence, signer classification, strict typed-record matching, and
  display-text-independent evaluation.
- `OAC-Service/`, `OAC-Launcher/`, `shared/oac_ipc.h`, and `shared/oac_lease.h`: restricted
  controller, identity-checked status IPC, one serialized caller-token launch transaction,
  service-owned target job, bounded two-channel evidence polling, central policy enforcement, and a
  backend-independent lease-state seam. The service keeps target inspection off the health loop,
  queues incremental memory/thread slices through one coalescing worker slot, and reports strict
  coverage and latency metrics to the launcher.
- Package/install and VM harness support for the service boundary, production session lifecycle and
  race tests, and Driver Verifier acceptance.

The current driver advertises production session control, launch tickets, session liveness, typed
evidence, and paged snapshots. Production configuration/scan, signed-manifest, signed-policy, and
backend capabilities remain unavailable.

## Current local validation

| Check | Result |
|---|---|
| `Debug|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| `Release|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| Current Debug and Release `OAC-Protocol-Unit.exe` | Passed; `477/477` in each configuration, including scheduler and typed-policy regression coverage |
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

Acceptance commit `5c476c246462c968d98185c6db159fdaf6a0238d` passed on Microsoft Windows
11 Pro 10.0.26100 build 26100 in a networkless Generation 2 Hyper-V VM with test signing enabled
and Secure Boot disabled. The host accepted 30 exact result records, including five protocol
executions and thirteen client, launcher, and preflight executions. The campaign passed production
service identity and direct-open boundaries, two standard-user suspended launches with
creation-time binding, exact-handle confirmation, verified job assignment, and first-thread resume.
It also proved service-crash and graceful-stop termination of both target and child, SCM recovery,
idempotent explicit revoke, and monotonic session-loss transitions from sequence `0` to `1` to `2`
with reasons `none`, `service exit`, and `requested shutdown`.

The restricted service completed all 26 queued scan slices and six full memory/thread sweeps with
no coalesced, cancelled, or failed slice. It inspected 1,114 memory regions and 17 threads; the
maximum measured health-loop delay was 297 ms, scan-slice duration 85.259 ms, and thread suspension
8.699 ms, all within the campaign bounds. Exact remove/reinstall, per-file cleanup and tombstone
races, the armed renamed-driver load gate, kernel provenance, and standard Driver Verifier passed.
Final Verifier flags were clear, both OAC services were stopped, the VM was Off with zero adapters,
and there were zero crash events and zero minidumps. The driver-free unit suite passed `477/477`;
each of four driver-backed protocol executions passed `129/129`. Driver Verifier recorded three OAC
loads and three unloads. The validated result ZIP SHA-256 was
`64DB55D10284C8C07C599A821C86D866B558FDAF86E21C146EE9D91127BEADEA`.

The exact status, host-manifest, and host-log SHA-256 values are
`CB277327E5DC8BAD1EE6BC175DFE5FF7741F0B160C21B7B106EA987B5C8EB466`,
`8509BBA22C035B2C3D9D587D6E00B8624B7DC2D786A215910F5683D13ACECF12`, and
`029896B7C34845C6BA27FAA730BD0FEDFAD7850D6FCD3E5579AEF8953BA478B8`.
After recording these values, the exact VM, checkpoint, VHD/AVHDX, package, seed, evidence, and
campaign directory were deleted. Under `C:\OAC-VM`, only the verified Windows installation ISO
remains.

## Current pending gates

- Hosted Debug/Release build, unit, and repository-validation checks passed on PR #13 and remain
  required for each merge.
- WP-09 signed game-manifest authorization is the next implementation milestone.
- The Windows 10/11/Server, HVCI/VBS, hardware, and game-compatibility matrix remains incomplete.

No milestone is described as production-ready. The control plane still lacks signed manifests,
signed runtime policy, and authenticated backend delivery listed above.
