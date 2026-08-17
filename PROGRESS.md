# OAC hardening progress

**Status date:** 2026-08-17

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

The current WP-01 through WP-04 source foundation is integrated and locally validated in the working tree
that started from the frozen baseline. Its commit-bound disposable-VM result is still pending.
Status requires both source and evidence; source present is not the same as an accepted work
package.

| Work package | Status | Current evidence or next gate |
|---|---|---|
| WP-00 Baseline, docs, tests | Locally validated; CI pending | Baseline recorded, docs updated, Debug/Release unit CI configured; both local configurations pass |
| WP-01 Production protocol foundations | Source integrated; acceptance pending | Production ABI, explicit message types, validators, stable IDs, event schema, pure units, and available driver dispatch present; final host and VM results pending |
| WP-02 Service and device identity | Source integrated; acceptance pending | Restricted service, identity-checked launcher IPC, production device ACL, installer and VM boundary phase present; disposable-VM results pending |
| WP-03 Per-file session state | Source integrated; acceptance pending | File contexts, process/file/session identity, diagnostic/production exclusion, rundown, cleanup/close, generation, runtime race, live-target tombstone, and retained-file owner-exit tests present; VM results pending |
| WP-04 Launch ticket and early binding | Source integrated; acceptance pending | One-use ticket ABI, creation-time creator/path binding, serialized service launch under the caller token, exact process-handle confirmation, hostile units, and VM acceptance source are present |
| WP-05 Job and liveness | Planned | No service-owned target job or complete target revocation exists |
| WP-06 Alert/event/snapshot transport | Planned | Typed event schema exists; no production event transport is advertised or dispatched |
| WP-07 Bounded service scheduler | Planned | No independent health loop or bounded worker scheduler exists |
| WP-08 Rule catalog and policy engine | Planned | Stable IDs exist; no central production policy evaluator |
| WP-09 Signed game manifest | Planned | No manifest verifier or key scope |
| WP-10 Signed policy/update model | Planned | Existing vulnerable-driver hash snapshot is not the planned signed policy channel |
| WP-11 Backend session abstraction | Planned | No backend lease, authenticated upload, or replay service |
| WP-12 Scanner modularization | Planned | Refactor behind tests; preserve lab behavior |
| WP-13 Game/server integration | Planned | No current game-specific server detector |
| WP-14 Production release engineering | Planned | Signing/HLK, SBOM, updates, privacy, and operations remain prerequisites |

WP-02 and WP-03 are deliberately not marked complete.

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
- `OAC/main.c`: production negotiate/claim/status and launch-ticket dispatch, plus lab-only
  diagnostic authorization.
- `OAC-Service/`, `OAC-Launcher/`, and `shared/oac_ipc.h`: restricted controller, identity-checked
  status IPC, and one serialized caller-token launch transaction.
- Package/install and VM harness changes for the service boundary, production session lifecycle/race test, and
  Driver Verifier rerun.

The current driver advertises production session control and launch tickets. Scan, event, CPU,
revoke, signed-manifest, signed-policy, and backend capabilities remain unavailable.

## Current local validation

| Check | Result |
|---|---|
| `Debug|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| `Release|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| Debug and Release `OAC-Protocol-Unit.exe` | Passed; `280/280` in each configuration |
| Release driver PREfast with `DriverMinimumRules` | Passed; zero reported warnings and errors |
| `InfVerif /w OAC/OAC.inf` and WDK `Inf2Cat` | Passed; zero warnings and errors |
| `tools/Test-OACRepository.ps1` (seven PowerShell, eleven XML, five YAML, one Python) | Passed |
| Markdown local-link resolution across the repository | Passed |
| Parse all five `.github` YAML files with PyYAML | Passed |
| `git diff --check` across the shared working tree | Passed |

`actionlint`, Clang-Tidy, and PSScriptAnalyzer are not installed on this workstation. The current
CI workflow does not yet provide CodeQL, SBOM generation, or secret-scanning evidence. These are
explicit remaining CI/static-analysis gaps rather than implied passes.

## Current pending gates

- Run the full driver-backed protocol suite in a disposable VM, including the production session lifecycle and
  bounded cleanup race.
- Run the `LabMode=0` service/launcher/direct-open boundary phase, including the standard-user
  suspended launch, exact creation-time bind, handle confirmation, and resume evidence.
- Run standard Driver Verifier on the current driver and record crash/dump and cleanup state.
- Record the exact final commit, Windows build, security configuration, commands, exits, and
  evidence location before changing WP-02 or WP-03 to complete.

No milestone is described as production-ready or as a complete hardened foundation. The minimal
control plane still lacks job/liveness containment, production telemetry, policy, signed manifest,
and backend work listed above.
