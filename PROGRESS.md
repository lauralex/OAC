# OAC hardening progress

**Status date:** 2026-08-20

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

WP-01 through WP-10 form the accepted production-control, target-lifetime, local-evidence,
bounded-scheduling, signed-build, and signed-policy foundation. The WP-11 backend-session source is
implemented and awaiting its commit-bound runtime campaign. Acceptance commit
`865a9f9b5d665c1c69fcf8b39486722046d6647f` passed the commit-bound disposable-VM and standard
Driver Verifier campaign described below. Status still distinguishes source, evidence, and the
remaining production-hardening work packages.

| Work package | Status | Current evidence or next gate |
|---|---|---|
| WP-00 Baseline, docs, tests | Tested foundation | Baseline recorded; Debug/Release builds and units, repository validation, packaging, and the current VM campaign passed; PR #13 hosted checks passed |
| WP-01 Production protocol foundations | Tested foundation | Production ABI, explicit message types, validators, stable IDs, event schema, pure units, driver dispatch, and driver-backed protocol execution passed on the named campaign |
| WP-02 Service and device identity | VM-tested foundation | Restricted service, identity-checked launcher IPC, production device ACL, exact install/remove, standard-user status, and direct-open denials passed on the named campaign |
| WP-03 Per-file session state | VM-tested foundation | File/process/session identity, protocol exclusion, rundown, cleanup/close, generation, runtime race, live-target tombstone, and owner-exit cases passed on the named campaign |
| WP-04 Launch ticket and early binding | Implemented; VM tested | One-use ticket, creation-time creator/path binding, suspended caller-token launch, exact process-handle confirmation, resume, hostile units, and Driver Verifier passed on the named campaign |
| WP-05 Job and liveness | Implemented; VM tested | Service-owned kill-on-close job, pre-resume assignment, explicit idempotent revoke, session-loss latch, lease-state evaluator, and bounded crash/stop process-tree tests passed on the named campaign |
| WP-06 Alert/event/snapshot transport | Implemented; VM tested | Separate retained-alert and overwrite-event queues, strict acknowledgement/cursor rules, persistent loss provenance, production loss revocation, service polling, and frozen paged kernel-module snapshots passed the named campaign |
| WP-07 Bounded service scheduler | Implemented; VM tested | Independent health loop, one-slot worker queue, cancellation, incremental memory/thread sampling, fixed budgets, strict metrics, and shared resume guard passed the named campaign |
| WP-08 Rule catalog and policy engine | Implemented; VM tested | Fixed catalog, five-level confidence, seven actions, three deployment modes, typed signer state, service enforcement, display-text independence, and integrated VM/Verifier execution passed on the named campaign |
| WP-09 Signed game manifest | Implemented; VM tested | Canonical record, detached CMS verification, protected signer pin, exact build/signer checks, expiry, rollback state, launch integration, and negative VM cases passed on the named campaign |
| WP-10 Signed policy/update model | Implemented; VM tested | Canonical signed policy, protected signer pin, game/build/channel scope, expiry, component compatibility, persistent replay state, explicit rollback authorization, emergency revocation, and integrated VM/Verifier execution passed on the named campaign |
| WP-11 Backend session abstraction | Source present; acceptance pending | Strict transport records and interface, protected mock backend, nonce replay rejection, bounded lease and acknowledgement state, fixed evidence queue, driver binding, and failure-policy tests are implemented; final VM/Verifier evidence is pending |
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
- `shared/oac_policy.h` and `shared/oac_policy.c`: C-compatible stable rule identities,
  Observe/Enforce/Strict decisions, five-level policy confidence, signer classification, strict
  typed-record matching, and display-text-independent evaluation.
- `shared/oac_signed_policy.h` and `shared/oac_signed_policy.c`: fixed canonical policy and cache
  records, bounded scope/time/component validation, replay and equivocation rejection, explicit
  rollback authorization, preserved historic high-water state, and emergency revocation.
- `shared/oac_manifest.h` and `shared/oac_manifest.c`: fixed canonical manifest and rollback-state
  records, hostile-input validation, exact file/signer identity, and deterministic high-water
  decisions.
- `shared/oac_backend.h` and `shared/oac_backend.c`: transport-independent session, renewal,
  evidence, and acknowledgement records; strict correlation and time bounds; replay-window,
  acknowledgement, and queue-state decisions.
- `OAC-Service/backend.hpp` and `OAC-Service/backend.cpp`: the nonblocking transport interface,
  fixed-capacity evidence queue, lease lifecycle, driver binding digest, and protected deterministic
  test backend. A production network transport and remote persistence are intentionally not supplied.
- `OAC-Service/`, `OAC-Launcher/`, `shared/oac_ipc.h`, and `shared/oac_lease.h`: restricted
  controller, identity-checked status IPC, one serialized caller-token launch transaction,
  service-owned target job, bounded two-channel evidence polling, central policy enforcement, and
  backend-session status. At startup, the service authenticates the local policy and
  commits protected per-game/channel update state. Before arming a launch, it checks policy scope
  and validates a detached signed manifest against the locked executable, an explicitly provisioned
  signer pin, bounded compatibility and expiry, and protected per-game rollback state. It binds the
  verified manifest digest into driver session status. The service keeps target inspection off the health loop,
  queues incremental memory/thread slices through one coalescing worker slot, and reports strict
  coverage and latency metrics to the launcher.
- Package/install and VM harness support for the service boundary, production session lifecycle and
  race tests, and Driver Verifier acceptance.

The current driver advertises production session control, launch tickets, session liveness, typed
evidence, and paged snapshots. Production configuration/scan and backend capabilities remain
unavailable. Manifest and policy verification remain service responsibilities; the driver carries
the verified manifest digest as correlated session identity rather than parsing signatures.

## Current local validation

| Check | Result |
|---|---|
| `Debug|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| `Release|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| Current Debug and Release `OAC-Protocol-Unit.exe` | Passed; `608/608` in each configuration, including backend record/correlation, nonce replay, lease, queue, acknowledgement, signed-policy, and earlier protocol/policy coverage |
| Release driver PREfast with `DriverMinimumRules` | Passed; zero reported warnings and errors |
| Solution-wide Release C/C++ analysis | Passed; zero reported warnings and errors |
| WP-07 Release Clang-Tidy baseline | Service and diagnostic scanner projects passed with warnings treated as errors at `865a9f9`; WP-11 changes no scanner source |
| `InfVerif /w OAC/OAC.inf` and WDK `Inf2Cat` | Passed; zero warnings and errors |
| `tools/Test-OACRepository.ps1` (seven PowerShell, eleven XML, five YAML, one Python) | Passed |
| Markdown local-link resolution across the repository | Passed |
| Parse all five `.github` YAML files with PyYAML | Passed |
| `git diff --check` across the shared working tree | Passed |

`actionlint` and PSScriptAnalyzer are not installed on this workstation. The current CI workflow
does not yet provide CodeQL or SBOM-generation evidence. These are explicit remaining CI and
static-analysis gaps rather than implied passes.

## Current disposable-VM validation

Acceptance commit `865a9f9b5d665c1c69fcf8b39486722046d6647f` passed on Microsoft Windows
11 Pro 10.0.26100 build 26100 in a networkless Generation 2 Hyper-V VM with test signing enabled
and Secure Boot disabled. The host accepted 40 exact result records, including five protocol
executions and thirteen client, launcher, and preflight executions. The campaign accepted two
standard-user launches authorized by the canonical signed manifest and rejected modified,
wrong-build, expired, and rollback manifests before launch. It also rejected signed policies with
the wrong signer, scope, validity period, or rollback state, accepted one explicitly authorized
rollback, and committed an emergency revocation before refusing startup. Both successful launches
completed creation-time binding, exact-handle confirmation, verified job assignment, and first-
thread resume.
The campaign also proved service-crash and graceful-stop termination of target and child, SCM
recovery, idempotent explicit revoke, and monotonic session-loss transitions from sequence `0` to
`1` to `2` with reasons `none`, `service exit`, and `requested shutdown`.

The restricted service completed 38 queued scan slices and eight full memory/thread sweeps with no
coalesced, cancelled, or failed slice. It inspected 1,504 memory regions and 24 threads; the maximum
measured health-loop delay was 313 ms, scan-slice duration 151.377 ms, and thread suspension
36.533 ms, all within the campaign bounds. Exact remove/reinstall, per-file cleanup and tombstone
races, the armed renamed-driver load gate, kernel provenance, and standard Driver Verifier passed. Final
Verifier flags were clear, both OAC services were stopped, the VM was Off with zero adapters, and
there were zero crash events and zero minidumps. The driver-free unit suite passed `544/544`; each
of four driver-backed protocol executions passed `130/130`. Driver Verifier recorded three OAC
loads and three unloads. The validated result ZIP SHA-256 was
`6167983A1A6C8CAB53F1F603D816F5D015C9CE9C96CC5AE9F300386B51D7BA49`.

The exact status, host-manifest, and host-log SHA-256 values are
`74AD825D4AE6DDCD8424468390BC3667C3F3B078C5FB9737DC768369C72DCCA9`,
`B3FF7DDF83792C0CC2AB1A2EDB5FE42089DFC1DFF2B02445F9BA4D8EE3CAF381`, and
`3FC226F15632E1296CE243611844DAC8A66FB1D5125E6A396730D767482A0754`.
After recording these values, the exact VM, checkpoint, VHD/AVHDX, package, seed, and full campaign
directory were deleted. Under `C:\OAC-VM`, only the verified Windows installation ISO remains.

## Current pending gates

- Hosted Debug/Release build, unit, and repository-validation checks passed on PR #13 and remain
  required for each merge.
- WP-11 requires its final commit-bound VM/Verifier campaign. A real online admission boundary still
  requires a production authenticated transport, backend service, and durable evidence storage
  behind the implemented interface.
- The Windows 10/11/Server, HVCI/VBS, hardware, and game-compatibility matrix remains incomplete.

No milestone is described as production-ready. The control plane still lacks manifest-key rotation
and revocation metadata, production backend deployment, and the release controls listed above.
