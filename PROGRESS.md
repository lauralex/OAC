# OAC hardening progress

**Status date:** 2026-08-20

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

WP-01 through WP-12 form the accepted production-control, target-lifetime, evidence,
bounded-scheduling, signed-build, signed-policy, backend-session, and scanner-organization
foundation. Implementation commit `67d3f616cdb13f1ac10877d067da1b54cca5e51c` passed the
commit-bound disposable-VM and standard Driver Verifier campaign described below. Status still
distinguishes source, evidence, and the remaining production-hardening work packages.

| Work package | Status | Current evidence or next gate |
|---|---|---|
| WP-00 Baseline, docs, tests | Tested foundation | Baseline recorded; Debug/Release builds and units, repository validation, packaging, and the current VM campaign passed; PR #18 hosted checks passed |
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
| WP-11 Backend session abstraction | Implemented; VM tested | Strict transport records and interface, protected mock backend, nonce replay rejection, bounded lease and acknowledgement state, fixed evidence queue, driver binding, target-tree failure policy, and fresh recovery passed on the named campaign |
| WP-12 Scanner modularization | Implemented; tested | Kernel inventory and process/handle scans are separated from integrity orchestration; common Windows ownership helpers and a tested client-option parser replace duplicate code; Debug/Release, static analysis, package, VM, Driver Verifier, and PR #18 hosted gates passed |
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
- `OAC/evidence.c` and `OAC/protection.c`: callback-safe typed publication, independent retained-alert
  and overwrite-event queues, and explicit loss accounting.
- `OAC/scanner.c`, `OAC/scanner_modules.c`, and `OAC/scanner_process.c`: scanner lifecycle and
  integrity checks, kernel-module inventory and frozen snapshots, and process/thread/handle
  cross-views, respectively. `OAC/scanner_internal.h` keeps only the small interface shared by
  those implementation files.
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
- `shared/oac_windows.hpp` and `OAC-Client/client_options.*`: shared move-only Windows resource
  ownership, text and optional-API helpers, plus a driver-free command-line parser used by both the
  scanner executable and its unit tests.
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
| Current Debug and Release `OAC-Protocol-Unit.exe` | Passed; `623/623` in each configuration, including client-option parsing and shared text helpers plus the existing backend, policy, manifest, protocol, lifetime, evidence, and scheduler coverage |
| Release driver PREfast with `DriverMinimumRules` | Passed; zero reported warnings and errors |
| Solution-wide Release C/C++ analysis | Passed; zero reported warnings and errors |
| Current Clang-Tidy | All eight `OAC-Client` translation units passed with warnings treated as errors; the four changed service translation units also passed targeted analysis |
| `InfVerif /w OAC/OAC.inf` and WDK `Inf2Cat` | Passed; zero warnings and errors |
| `tools/Test-OACRepository.ps1` (seven PowerShell, eleven XML, five YAML, one Python) | Passed |
| Markdown local-link resolution across the repository | Passed |
| Parse all five `.github` YAML files with PyYAML | Passed |
| `git diff --check` across the shared working tree | Passed |

`actionlint` and PSScriptAnalyzer are not installed on this workstation. The current CI workflow
does not yet provide CodeQL or SBOM-generation evidence. These are explicit remaining CI and
static-analysis gaps rather than implied passes.

## Current scanner-modularization validation

Implementation commit `67d3f616cdb13f1ac10877d067da1b54cca5e51c` passed on Microsoft Windows
11 Pro 10.0.26100 build 26100 in a networkless Generation 2 Hyper-V VM with test signing enabled
and Secure Boot disabled. The host accepted 41 exact formal result records, including five protocol
executions and thirteen client, launcher, and preflight executions. All formal and auxiliary result
sets matched. The reorganized kernel scanner, shared user-mode Windows support, and client option
parser completed the unchanged baseline and Driver Verifier acceptance paths.

The campaign also reran production identity, signed-manifest and signed-policy authorization,
backend replay, acknowledgement-loss and lease-loss containment, fresh-session recovery,
removal/reinstall, driver-gate, kernel-provenance, retained-evidence, snapshot, and bounded-scheduler
cases. The service completed 35 queued scan slices and seven full memory/thread sweeps, inspecting
1,367 memory regions and 21 threads. Maximum measured health-loop delay was 437 ms, scan-slice
duration 43.498 ms, and thread suspension 5.166 ms. Driver Verifier reported three OAC loads and
three unloads, then reset and finished inactive. Both OAC services were stopped, the VM was Off with
zero network adapters, and there were zero crash events and zero minidumps. Debug and Release
driver-free unit runs passed `623/623`.

The validated result ZIP SHA-256 was
`53713237C27A11BF843DCDCAC86EC354C1E723615D62C7EEA769501F2FEAE466`.
The exact final-status, host-manifest, and host-log SHA-256 values are
`FAC52438BD12AE222816E0BD9D5493F47B666BBC311C745BEBB1A205133454A0`,
`F37FC3AAD2E0D359768265A07216F7B8307251C9E1FBDE4D960154EF32618F35`, and
`4AD8029C94FF7E203769F875C43D8FBA41816502D9A0D29110AFFB2677A2839B`.
The compact evidence bundle is stored outside the repository at
`C:\OAC-VM\evidence\20260820-67d3f61-scanner-modules`. After preserving and verifying it, the exact
disposable VM, checkpoint, VHD/AVHDX, package, seed, and full campaign directory were deleted.

### Previous backend-foundation campaign

Implementation commit `47c04005e66f1fd61ae9fe9a35260f19ee447dd1` previously passed the same
Windows build and containment model for WP-01 through WP-11. Its validated result ZIP SHA-256 was
`18DF30A66D52B6FAAE163D4AF0458BC9D83263B02BF82EBDA4736205890259C5`; the compact historical
bundle remains at `C:\OAC-VM\evidence\20260820-47c0400-backend-session`.

## Current pending gates

- Hosted Debug/Release build, unit, and repository-validation checks remain required for each merge.
- A real online admission boundary still requires a production authenticated transport, backend
  service, credential lifecycle, and durable evidence storage behind the implemented interface.
- WP-12 scanner modularization has commit-bound runtime acceptance and PR #18 hosted acceptance.
  The refactor does not add or relax a scanner capability.
- WP-13 game/server integration is the next product milestone.
- The Windows 10/11/Server, HVCI/VBS, hardware, and game-compatibility matrix remains incomplete.

No milestone is described as production-ready. The control plane still lacks manifest-key rotation
and revocation metadata, production backend deployment, and the release controls listed above.
