# OAC hardening progress

**Status date:** 2026-08-21

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

**Reviewed source baseline:** `90dfdfaa9178cbc0274394d1aec77b40ef643762`

WP-01 through WP-12 form the accepted production-control, target-lifetime, evidence,
bounded-scheduling, signed-build, signed-policy, backend-session, and scanner-organization
foundation. WP-13 adds a portable game/server event interface and one deterministic behavioral
detector. WP-14 adds a source-bound unsigned release candidate, deterministic metadata, SPDX SBOM,
private-symbol separation, support/privacy policy, and operational promotion controls. WP-15 adds a
fail-closed production endpoint admission gate, loaded-driver trust, signed runtime-module policy,
and bounded typed target observations. WP-16 adds a native mutually authenticated network
transport, a separate durable .NET admission backend, signed remote-policy refresh, and a typed
game-server adapter.
Endpoint-trust implementation commit `974d2c474ff9515c5f11ab313bf644bf7dcbe89a` passed the exact
signed-package, networkless Windows 11 build 26100, and standard Driver Verifier campaign described
below.
Backend-admission implementation commit `085c8fe83fbfa4862fe425be9f1d7fae94e52c1f` passed the
managed backend suites and the complete endpoint-regression campaign described below.
Windows-runtime implementation commit `67d3f616cdb13f1ac10877d067da1b54cca5e51c`
passed the commit-bound disposable-VM and standard Driver Verifier campaign described below.
Portable game-integration implementation commit `8eca1747680f7dc9ad084d1e1897f30bfec08d83`
passed local and PR #19 hosted acceptance. Status still distinguishes source, evidence, and the
remaining production-hardening work.

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
| WP-13 Game/server integration | Implemented; tested | Canonical authoritative movement records, replay-safe state, bounded movement/velocity rules, combined behavior and endpoint risk, hostile driver-free tests, and a public integration guide passed local and PR #19 hosted acceptance |
| WP-14 Production release engineering | Implemented; local acceptance | Exact unsigned public/lab/private-symbol bundles, source and toolchain metadata, SPDX SBOM, hostile candidate validation, CI artifact separation, and reviewed signing, update, support, privacy, and operations contracts are present; production certification/signing and deployed operations remain external gates |
| WP-15 Production endpoint trust | Implemented; VM tested | Exact production scan/configuration, explicit completeness, frozen loaded-driver inventory, trust/hash/family policy, runtime-module authorization, typed memory/thread/lifecycle observations, and fail-closed evidence handling passed the complete local and Windows 11/Driver Verifier acceptance gates at `974d2c4` |
| WP-16 Production backend admission | Implemented; accepted | HTTPS mutual TLS, role-separated certificate rotation, signed remote-policy refresh and crash-safe cache selection, durable lease/replay/evidence/game state, backend restart recovery, and the typed game adapter passed the managed and shared-contract suites; the exact endpoint package passed the full Windows 11 and Driver Verifier regression campaign at `085c8fe`, and PR #22 passed hosted checks |

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
- `OAC/main.c`: production negotiate/claim/status/revoke, endpoint configuration/scan, and
  launch-ticket dispatch, plus lab-only diagnostic authorization.
- `OAC/evidence.c` and `OAC/protection.c`: callback-safe typed publication, independent retained-alert
  and overwrite-event queues, and explicit loss accounting.
- `OAC/scanner.c`, `OAC/scanner_modules.c`, and `OAC/scanner_process.c`: scanner lifecycle and
  integrity checks, kernel-module inventory and frozen snapshots, and process/thread/handle
  cross-views, respectively. The same bounded primitives feed a narrow production scan with explicit
  completeness. `OAC/scanner_internal.h` keeps only the small interface shared by those
  implementation files.
- `shared/oac_policy.h` and `shared/oac_policy.c`: C-compatible stable rule identities,
  Observe/Enforce/Strict decisions, five-level policy confidence, signer classification, strict
  typed-record matching, and display-text-independent evaluation.
- `shared/oac_signed_policy.h` and `shared/oac_signed_policy.c`: fixed canonical policy and cache
  records, bounded scope/time/component validation, replay and equivocation rejection, explicit
  rollback authorization, preserved historic high-water state, and emergency revocation.
- `shared/oac_manifest.h` and `shared/oac_manifest.c`: fixed canonical manifest and rollback-state
  records, hostile-input validation, exact file/signer identity, bounded runtime-module policy, and
  deterministic high-water decisions.
- `shared/oac_driver_trust.*` and `shared/oac_driver_hash_policy.hpp`: common file and loaded-driver
  trust evaluation, generated denied hashes, signer classification, and blocked-family decisions.
- `shared/oac_backend.h` and `shared/oac_backend.c`: transport-independent policy, session, renewal,
  evidence, acknowledgement, and game-decision records; strict correlation and time bounds;
  replay-window, acknowledgement, and queue-state decisions.
- `OAC-Service/backend.*` and `OAC-Service/backend_http.*`: the nonblocking transport interface,
  fixed-capacity evidence queue, lease lifecycle, driver binding digest, protected deterministic
  test transport, and bounded WinHTTP mutual-TLS production transport.
- `OAC-backend/`: a separate .NET 8 admission service with role-separated client certificates,
  signed-policy delivery, sealed alternating state snapshots, durable evidence/game append records,
  restart recovery, explicit revocation, real loopback mutual-TLS tests, and a typed game-server
  adapter.
- `shared/oac_game.h` and `shared/oac_game.c`: portable canonical game-event construction, strict
  server identity and replay validation, bounded movement policy, persistent detector state, and
  explainable behavior/endpoint risk decisions. They have no Windows, driver, transport, game-engine,
  or account-system dependency.
- `OAC-Service/endpoint_preflight.*`, `OAC-Service/runtime_module.*`,
  `OAC-Service/target_scanner.*`, `OAC-Launcher/`, `shared/oac_ipc.h`, and `shared/oac_lease.h`:
  fail-closed endpoint admission, runtime-module authorization, typed bounded target observations,
  launcher status, and lease state. The wider `OAC-Service/` remains the restricted
  controller, identity-checked status IPC, one serialized caller-token launch transaction,
  service-owned target job, bounded two-channel evidence polling, central policy enforcement, and
  backend-session status. At startup, the service authenticates the local policy and
  commits protected per-game/channel update state. Before arming a launch, it checks policy scope
  and validates a detached signed manifest against the locked executable, an explicitly provisioned
  signer pin, bounded compatibility and expiry, runtime-module scope, and protected per-game
  rollback state. Before opening launcher IPC it requires a complete correlated kernel scan,
  evaluates loaded-driver trust/hash/family policy, and obtains backend acknowledgement. It binds
  the verified manifest digest into driver session status. The service keeps target inspection off
  the health loop, queues incremental memory/thread slices through one coalescing worker slot, and
  reports strict coverage, observations, and latency metrics to the launcher.
- `shared/oac_windows.hpp` and `OAC-Client/client_options.*`: shared move-only Windows resource
  ownership, text and optional-API helpers, plus a driver-free command-line parser used by both the
  scanner executable and its unit tests.
- Package/install and VM harness support for the service boundary, production session lifecycle and
  race tests, and Driver Verifier acceptance.
- `config/release-profile.json`, `Directory.Build.targets`, and the release-candidate tools: exact
  release/driver/compatibility binding, reviewed INF metadata, leaf-only PDB records, canonical
  manifests and checksums, shared Windows file-version resources, SPDX 2.3 inventory,
  private-symbol separation, and hostile artifact validation. Public CI uploads only the unsigned
  production-component and isolated-lab bundles.

The current driver advertises production session control, launch tickets, session liveness, typed
evidence, paged snapshots, kernel scans, and the driver-load gate. Manifest, file trust, and policy
verification remain service responsibilities; the driver carries correlated digests and scan
identity rather than parsing signatures.

## Current local validation

| Check | Result |
|---|---|
| `Debug|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| `Release|x64` full solution rebuild, `/W4 /WX`, `/nodeReuse:false` | Passed; zero warnings and errors |
| Current Debug and Release `OAC-Protocol-Unit.exe` | Passed; `739/739` in each configuration, including endpoint-scan completeness and correlation, loaded-driver trust policy, runtime-module authorization, typed target observations, canonical game events, backend, policy, manifest, protocol, lifetime, evidence, and scheduler coverage |
| Release driver PREfast with `DriverMinimumRules` | Passed; zero reported warnings and errors |
| Solution-wide Release C/C++ analysis | Passed; zero reported warnings and errors |
| Current Clang-Tidy | All sixteen `OAC-Service` build translation units passed with warnings treated as errors; the unchanged nine-translation-unit `OAC-Client` baseline remains current |
| `InfVerif /w OAC/OAC.inf` and WDK `Inf2Cat` | Passed; zero warnings and errors |
| `tools/Test-OACRepository.ps1` (ten PowerShell, thirteen C#, thirteen XML, five YAML, one Python) | Passed |
| Release profile and candidate reconstruction under Windows PowerShell 5.1 and PowerShell 7 | Passed; all five hostile mutations rejected in both engines |
| Generated `sbom.spdx.json` against the official SPDX 2.3 Draft 7 JSON schema | Passed |
| Markdown local-link resolution across the repository | Passed |
| Parse all five `.github` YAML files with PyYAML | Passed |
| `git diff --check` across the shared working tree | Passed |

`actionlint` and PSScriptAnalyzer are not installed on this workstation. The current workflow now
generates and hostile-tests the unsigned Release candidate and SPDX SBOM; it still does not provide
CodeQL or production artifact attestation. Those are explicit remaining CI and static-analysis
gaps rather than implied passes.

## Current release-engineering validation

The WP-14 candidate has three exact trees: unsigned production components, private full symbols,
and isolated lab tools. Release binaries record only their PDB leaf name. The public manifest binds
the clean source commit, normalized source timestamp, exact toolchain and compatibility values, and
every artifact size and SHA-256. The SPDX 2.3 document covers the same public files and passed the
official JSON schema.

Both supported PowerShell engines created and reconstructed the candidate, then rejected payload,
manifest, symbol, extra-public-file, and missing-lab-marker mutations. Public CI is configured to
upload only `public/` and `lab/`; private symbols remain available to a controlled promotion runner
but are not published. Microsoft certification, protected signing keys, final signed-artifact
manifests, platform admission, and staged deployment are documented promotion gates rather than
claims about the unsigned CI output.

## Current game/server integration validation

The portable WP-13 interface constructs exact authoritative movement records scoped to game,
build, backend session, match, player pseudonym, replay identity, sequence, and server tick. The
reference detector rejects replay and state corruption without mutation, reports forward gaps,
checks tick-scaled horizontal and vertical movement plus reported velocity, handles explicit server
corrections, and combines bounded behavior risk with a separately retained endpoint-risk input.

Debug and Release driver-free suites pass `663/663`, including hostile schema, identity, flags,
reserved data, rules, replay, coordinate extremes, threshold, saturation, and partial-output cases.
Implementation commit `8eca1747680f7dc9ad084d1e1897f30bfec08d83` also passed the PR #19 hosted
Debug/Release builds, `663/663` tests in each configuration, and repository validation. WP-13
changes no driver, service, installer, or privileged Windows runtime behavior. Rebuilding a
disposable VM would add no meaningful evidence for this portable server-side slice, so the existing
WP-01 through WP-12 VM/Verifier evidence remains unchanged and no new VM campaign was run.

## Current backend-admission validation

The backend project restores from committed lock files and builds with nullable analysis, current
.NET analyzers, and warnings treated as errors. Its Debug and Release suites pass `26/26` and
exercise exact policy delivery, nonce/request replay, lease expiry, revocation, active-session
exclusion, durable evidence
acknowledgement, partial-batch recovery, game-state replay, backend restart, role-separated client
certificates, bounded certificate rotation, real loopback mutual TLS, typed game-adapter response
correlation, and fail-closed ambiguous transactions. The native driver-free suite independently
validates the shared policy/game wire layouts and hostile input.

The reference backend deliberately uses one protected writer and bounded local files. It is useful
for a controlled deployment and as an executable contract, but it does not claim managed database,
replication, service discovery, automated backup, fleet credential enrollment, or operational SLOs.

Implementation commit `085c8fe83fbfa4862fe425be9f1d7fae94e52c1f` also passed the exact signed
Debug package, networkless Windows 11 Pro 10.0.26100 build 26100, and standard Driver Verifier
campaign. The host accepted 41 exact formal results: five protocol executions and thirteen client,
launcher, and preflight executions. Signed-policy signature, scope, expiry, replay, authorized
rollback, and emergency-revocation cases passed; backend nonce replay, withheld acknowledgement,
and lease loss each failed closed and recovered through a fresh session. The bounded worker
completed 30 slices and six sweeps with no failed, cancelled, or skipped thread work. Driver
Verifier recorded three OAC loads and three unloads, then reset and finished inactive. There were
zero crash events and minidumps, both OAC services were stopped, and final containment passed.
The validated results ZIP SHA-256 was
`4C02D6E2A53BBE15D49D0E54E93F68970351EA6EC3D928C7BA0033D744434025`; the byte-identical external
and archived final status SHA-256 was
`AEED6543E28FF274FEBEAAE0473A89CE9484432D15EFAF67E8DD9E6C22FFFAFE`. The disposable VM, disks,
package, seed, and evidence directory were removed after recording these hashes.

## Previous endpoint-trust validation

Implementation commit `974d2c474ff9515c5f11ab313bf644bf7dcbe89a` passed on Microsoft Windows
11 Pro 10.0.26100 build 26100 in a networkless Generation 2 Hyper-V VM with test signing enabled
and Secure Boot disabled. The host accepted 41 exact formal result records: five protocol-related
executions and thirteen client, launcher, and preflight executions. Every formal and auxiliary
result set matched. Production endpoint admission, frozen loaded-driver trust evaluation, runtime
module authorization, the armed driver gate, signed build/policy boundaries, backend replay and
failure recovery, exact remove/reinstall, kernel provenance, and target-tree containment all passed.

The bounded target worker completed 37 of 37 queued slices and eight full sweeps, inspecting 1,424
memory regions and 24 threads with no failed, cancelled, or skipped thread work. Maximum measured
health-loop delay was 406 ms, scan-slice duration 107.878 ms, and thread suspension 1.750 ms. Driver
Verifier reported three OAC loads and three unloads, then reset and finished inactive. Both OAC
services were stopped, the VM was Off with zero network adapters, and there were zero crash events
and zero minidumps.

The exact package-manifest and seed-ISO SHA-256 values were
`9B6224EC4CFE71F960DB59A0E5F29CF00E747A9CEBDCA2A37D87567BBFB55BEA` and
`FB00EC1084AE705D921F49B214B5D42F99A91AA2E0A8663DE1976719289D9F20`. The validated result ZIP,
final status, host manifest, and host log SHA-256 values were
`89241D005E2A16CA4CBC3A0F1C658E128E2DB3D7C5B7E91010751A3242182EC2`,
`93CCB5582AFDE9917429627B89FD3BE23E71179FDCC98E252E8F491DBC46ABAA`,
`6CD0FD5F09DF2745FB298D63A4141CB64EF4A520A41EE8DDA7291F828AFA8A74`, and
`7633DE4B615DFC307FD37BE455DCE12EE44E0D10DF3DEBE2B518D5D01E1A9D3F`.
After recording those results, the disposable VM, checkpoint, VHD/AVHDX, package, seed, and full
campaign directory were deleted as test artifacts.

## Previous scanner-modularization validation

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
The compact evidence bundle was verified outside the repository before later workspace cleanup. Its
hashes above remain the durable record; the exact disposable VM, checkpoint, VHD/AVHDX, package,
seed, full campaign directory, and compact bundle were deleted.

### Previous backend-foundation campaign

Implementation commit `47c04005e66f1fd61ae9fe9a35260f19ee447dd1` previously passed the same
Windows build and containment model for WP-01 through WP-11. Its validated result ZIP SHA-256 was
`18DF30A66D52B6FAAE163D4AF0458BC9D83263B02BF82EBDA4736205890259C5`; its compact historical bundle
was also removed during the requested workspace cleanup.

## Current pending gates

- Hosted Debug/Release build, unit, and repository-validation checks remain required for each merge.
- The production transport and single-node backend are implemented. A supported online service
  still requires managed deployment, fleet credential enrollment, service discovery, monitoring,
  backup/restore automation, capacity planning, and operational approval.
- WP-12 scanner modularization has commit-bound runtime acceptance and PR #18 hosted acceptance.
  The refactor does not add or relax a scanner capability.
- WP-13 game/server integration passed its local and PR #19 hosted acceptance. A real game still
  needs an engine binding, signed game-specific rules, representative workload tuning, and
  additional gameplay detectors beyond the included authenticated adapter and movement invariant.
- WP-14 source controls and operating contracts are implemented; hosted candidate generation and
  repository checks must pass before merge, while real certification/signing and operational
  approval remain deployment gates.
- WP-15 passed the complete local build, unit, analysis, release-profile, hostile-candidate,
  signed-package, Windows 11, and standard Driver Verifier gates at `974d2c4`.
- WP-16 passed its local managed suites, exact endpoint-regression VM/Verifier campaign, and PR #22
  hosted checks. WP-17 create-time job assignment, stable mapped-file identity, durable local
  evidence recovery, and manifest-key rotation is the next engineering milestone; representative
  module/JIT tuning remains separate deployment work.
- The Windows 10/11/Server, HVCI/VBS, hardware, and game-compatibility matrix remains incomplete.

No milestone is described as production-ready. The control plane still lacks manifest-key rotation
and revocation metadata, managed backend deployment, protected signing/certification, tuned game and
middleware policy, and an approved supported-platform rollout.
