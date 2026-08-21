# OAC test matrix

**Status:** WP-01 through WP-12 tested locally and in the disposable-VM campaign at implementation
commit `67d3f616cdb13f1ac10877d067da1b54cca5e51c` on Windows 11 build 26100. PR #18 hosted checks also
passed. WP-13 game/server contracts and the reference detector passed local and PR #19 hosted
driver-free acceptance at implementation commit `8eca1747680f7dc9ad084d1e1897f30bfec08d83`.
WP-14 adds the reviewed unsigned release boundary. WP-15 endpoint admission, loaded-driver trust,
runtime-module authorization, and target observation passed local gates plus the exact signed-package,
networkless Windows 11 build 26100, and standard Driver Verifier campaign at
`974d2c474ff9515c5f11ab313bf644bf7dcbe89a`.
WP-16 backend admission passed its managed mutual-TLS/durability suites and the complete endpoint
regression campaign at `085c8fe83fbfa4862fe425be9f1d7fae94e52c1f`.

**Frozen baseline:** `075ad2109f84cce90727f8ba65f87b807500e6b7`

Labels in this document are evidence states:

- **Tested:** executed for the named revision and environment.
- **Historical:** recorded from an earlier campaign but not rerun for the current source.
- **Source present:** implementation or test code exists, but its current acceptance run is pending.
- **Planned:** required before the associated milestone.
- **Unsupported:** outside the stated target.

## Host-safe checks

| Check | Current source | Current evidence |
|---|---|---|
| `Debug|x64` solution build | Workflow matrix configured | Current local and PR #19 hosted builds passed with zero warnings/errors |
| `Release|x64` solution build | Workflow matrix configured | Current local and PR #19 hosted builds passed with zero warnings/errors |
| `OAC-Protocol-Unit.exe` | C/C++ driver-free unit project included in both configurations | Current Debug and Release executables pass `739/739` |
| `OAC.Backend.Tests` | .NET 8 Debug/Release build with locked restore, nullable analysis, analyzers, and warnings as errors | Current suite has 26 configuration, direct-store, and real loopback mutual-TLS checks in each configuration |
| Managed deliverables | Framework-dependent backend publish and typed game-adapter package | CI builds and uploads both separately from the native endpoint candidate |
| Protocol layout assertions | Diagnostic, production, and game-event compile-time sizes/offsets | Compiled in both local configurations and on PR #19 |
| `InfVerif /w` | Required for package changes | Current local validation passed |
| PowerShell/Python/XML/YAML parse | Required repository checks | Current Windows PowerShell and PowerShell 7 validation passed |
| Clang-Tidy | Required for scanner changes | All sixteen current `OAC-Service` build translation units passed with warnings treated as errors; the unchanged nine-translation-unit `OAC-Client` baseline remains current |
| Driver PREfast | Required for driver/lifetime changes | Current local `DriverMinimumRules` run passed with zero warnings/errors |
| Secret scan | GitGuardian branch check configured | Required repository check |
| Release profile | Exact source/header/INF/SDK/artifact binding | Windows PowerShell 5.1 and PowerShell 7 validation passed |
| Release candidate | Canonical public/lab/private-symbol trees, manifests, SPDX SBOM, checksums, and CodeView/PDB matching | Creation and byte-exact reconstruction passed in both PowerShell engines |
| Candidate hostility | Payload, manifest, PDB, extra public file, and missing lab marker | All five mutations were rejected in both PowerShell engines |
| SPDX 2.3 | Generated public inventory against official Draft 7 JSON schema | Passed locally |

The workflow builds Debug and Release, runs
`x64/<Configuration>/OAC-Protocol-Unit.exe`, creates and hostile-tests the exact unsigned candidate,
uploads only its public and isolated-lab trees, and keeps the stable aggregate job name `build`.
The private symbol tree is not uploaded. A green hosted workflow is compile, pure-unit, SBOM, and
artifact-boundary evidence; it does not load the driver, sign a production release, or test Windows
service security.

### Driver-free production protocol coverage

The pure C/C++ unit source covers:

- C and C++ ABI compatibility, structure sizes/offsets, distinct IOCTLs, buffered transfer, and
  read/write access bits;
- exact `MessageType`/IOCTL matching and request/response correlation;
- strict version, length, ID, session, generation, flag, reserved, range, and alignment checks;
- negotiation, claim, and status requests and responses, including revoked-state consistency;
- stable rule/event IDs, severity, confidence, category, and the exact session transition matrix;
- event provenance rules and hostile none, binary, and UTF-16 payload cases, including dirty tails,
  embedded nulls, and invalid surrogate pairs;
- retained-alert acknowledgement, event-gap/loss reconciliation, record-channel classification,
  snapshot request/response/paging correlation, and lab-only overflow injection validation;
- launch-ticket layouts, strict canonical NT paths, expiry/cancel/replay decisions, exact process
  handles, response correlation, and terminal state invariants;
- explicit session-revoke layouts, status-latch consistency, idempotent transition expectations,
  and healthy/degraded/expired/revoked lease-state decisions; and
- launcher/service launch IPC layouts, hostile DOS paths, reserved fields, dirty tails, and success
  or rejection identity invariants; and
- canonical game-manifest and rollback-state layouts, hostile identities/names/reserved data,
  component compatibility, expiration, exact file/signer identity, rollback, and same-sequence
  equivocation; and
- canonical signed-policy and cache layouts, hostile identity/time/component/rule/operation fields,
  scope matching, replay, equivocation, explicit rollback, preserved historic high-water state, and
  emergency revocation; and
- backend policy, open, renewal, evidence, acknowledgement, and game-decision layouts; strict
  size/type/session/nonce/time correlation; replay-window bounds; sequence and acknowledgement
  monotonicity; fixed-queue and timeout outcomes; binding digest; mock restart; lease expiry; and
  revocation; and
- canonical server-authoritative movement layouts and construction; exact game/build/session/match/
  pseudonym/replay scope; hostile fields and rules; replay and state immutability; sequence/tick
  gaps; movement and velocity bounds; server correction; coordinate extremes; combined risk; and
  saturation; and
- strict scheduler metric states/counts/timestamps, fixed slice budgets, and real explicit plus
  scope-cleanup thread-resume paths.

This validates the schema and pure validators, not the kernel dispatcher or service boundary.

## Driver-backed protocol coverage

`OAC-Protocol-Test.exe` requires an installed, running test-signed driver in an isolated disposable
VM. Its current source includes the earlier diagnostic malformed-request, scan, CPU, finding, and
driver-gate coverage plus these production cases:

- claim denied before negotiation and production claim denied to a lab administrator;
- exact negotiation/claim/status correlation and malformed version, size, request ID, flags,
  `MessageType`, session, generation, mode, and reserved fields;
- bidirectional per-file exclusion between production negotiation/claim and privileged diagnostic operations;
- a second file may negotiate but cannot claim or use copied session credentials;
- a duplicated handle used from another process cannot use the owning file's session;
- cleanup/close removes authority and a replacement claim receives a different session ID and
  higher generation;
- four concurrent status workers each complete 32 valid warm-up requests, then race one final
  request with handle cleanup; completions must be valid or fail with a bounded close result;
- a replacement claim after the race advances generation;
- closing the controller with a live diagnostic target leaves a tombstone, rejects a replacement claim
  with `ERROR_BUSY`, and permits reclaim only after the target exits;
- after a production-session owner exits, a wrong-process holder of the exact old file object remains denied while
  a different file immediately claims a distinct, higher-generation session;
- malformed launch requests are rejected while diagnostic sessions receive `ERROR_NOT_SUPPORTED`
  for production arm, cancel, and confirm operations; and
- retained alerts survive a 10,000-record lower-priority burst, acknowledgements reject replay and
  undelivered cursors, concurrent producers preserve exact sequence/drop accounting, snapshot pages
  remain stable through close, full alert queues preserve existing data and latch first loss, and
  diagnostic overflow does not silently revoke lab authority; and
- explicit revoke rejects malformed provenance/reserved/size fields, increments the session-loss
  sequence once, and returns the same terminal result on repetition.

These tests exercise real file contexts, authorization, and rundown. Their current VM execution and
standard Driver Verifier run most recently passed at implementation commit
`085c8fe83fbfa4862fe425be9f1d7fae94e52c1f`.
Driver-free tests cover the launch wire contract, canonical
path rejection, expiry boundary, creator/path decision matrix, cancellation, exact handle fields,
and terminal state transitions. The VM production boundary exercises the real creation callback and
service-owned launch. The retained-alert, acknowledgement, event-gap, concurrent-publication,
overflow, snapshot-paging, and service alert-poll paths passed in the same baseline and Driver
Verifier campaign.

## Service and launcher coverage

The VM harness source now contains a bounded `LabMode=0` production-boundary phase that:

- starts the restricted `OACService` and requires its production claim;
- runs standard-user launcher status before failure, after service recovery, and after graceful
  restart;
- attempts direct driver opens as LocalSystem, a limited user, and an administrator and requires all
  three to fail;
- launches a signed target twice as the standard user, requires exact creation-time binding,
  process-handle confirmation, verified job assignment, and initial-thread resume;
- before those launches, requires modified, signed wrong-build, signed expired, and signed rollback
  manifests to fail at the exact manifest-verification stage;
- while the first target is live, queries the independent health loop and bounded worker and
  requires completed incremental memory/thread coverage within the health, slice, and suspension
  budgets with no cancellation or worker failure;
- proves service-process failure terminates the job-owned parent and child, then observes SCM
  recovery and exactly one file-cleanup or service-exit loss;
- proves graceful service stop explicitly revokes the session, terminates the second parent and
  child, and advances the loss sequence exactly once;
- replaces the installed policy with signed wrong-signature, expired, wrong-scope, rollback,
  authorized-rollback, and emergency fixtures and requires each exact accept or reject outcome;
- selects protected backend test scenarios and requires reused open-nonce rejection, target-tree
  termination after withheld evidence acknowledgement and lease loss, and a clean service recovery
  with a new backend session after each failure;
- stops the service and restores explicit lab mode before diagnostic tests;
- records cleanup separately so a failed boundary test cannot silently leave the wrong mode active.

The installer structurally reads back the service type, manual start, LocalSystem account, OAC
dependency, restricted service SID type, exact four-privilege list, fixed SID, binary paths, SYSTEM
owner/group, and exact query-status/start-only Administrators and Interactive ACL. It also verifies
a one-day reset policy with one restart after five seconds followed by no further action, including
non-crash failures. A targeted LocalSystem native-policy probe passed on Windows 11 24H2 build
26100. The complete installer and production-boundary VM paths now pass on that build. Dedicated
negative effective-service-right and reboot-persistence cases remain pending.

## Runtime matrix

| Environment or scenario | Evidence |
|---|---|
| Windows 11 Pro 24H2 build 26100, networkless Hyper-V, test signing | Most recently tested at `085c8fe`; 41 exact formal results, overall pass, Secure Boot disabled |
| Standard Driver Verifier on `OAC.sys` | Most recently tested at `085c8fe`; three loads and unloads, reset and inactive at completion, zero crashes/dumps |
| Production service identity, device ACL, standard-user launcher, admin direct-open denial | Most recently tested at `085c8fe`; status four times, launch twice, and LocalSystem/limited/admin direct opens denied |
| SCM owner/DACL effective rights and recovery persistence | Structural native-policy probe passed on build 26100; negative-right and reboot tests pending |
| Production per-file cleanup/close and concurrent status teardown | Most recently tested at `085c8fe` in baseline and Verifier protocol executions |
| Live-target tombstone and later retirement | Most recently tested at `085c8fe` in the driver-backed lifecycle suite |
| Standard-user service launch, creation-time binding, confirmation, job assignment, and resume | Most recently tested twice at `085c8fe` |
| Service-owned job, parent/child termination, crash recovery, graceful revoke | Most recently tested at `085c8fe`; both process trees terminated and SCM recovery completed |
| Retained alerts, event gaps, overflow provenance, concurrent publication, paged snapshots | Most recently tested at `085c8fe`; four driver-backed executions passed |
| Independent health loop and bounded target worker | Most recently tested at `085c8fe`; 30 slices, six sweeps, 422 ms maximum health delay, 106.140 ms maximum slice duration, 33.058 ms maximum suspension |
| Typed policy rules and service evaluation | Current driver-free tests pass `739/739`; integrated signed-policy service execution most recently passed at `085c8fe` |
| Signed main-executable manifest authorization | Most recently tested at `085c8fe`; two authorized launches passed and modified, wrong-build, expired, and rollback manifests were rejected |
| Signed policy selection and update state | Most recently tested at `085c8fe`; signer, scope, expiry, rollback, authorized rollback, emergency revocation, and cached-state selection passed |
| Backend session, lease, replay, and acknowledgement failure | Most recently tested at `085c8fe`; replay was rejected, post-start withheld acknowledgement and lease loss terminated the target tree, and both recovered through a fresh session |
| Production backend transport and durable admission service | Native WinHTTP transport builds and passes static analysis; managed Debug/Release `26/26` and real loopback mutual-TLS, role, rotation, restart, replay, lease, evidence, and game-decision tests pass. Managed deployment remains external. |
| Production endpoint admission and scan completeness | Most recently tested at `085c8fe`; the service admitted only after a complete correlated scan and backend acknowledgement |
| Loaded-driver trust, hash policy, and denied family | The exact signed-package startup path and shared trust evaluation most recently passed at `085c8fe`; broader driver-family and platform coverage remains planned |
| Runtime-module manifest authorization | The authorized runtime path most recently passed at `085c8fe`; hostile manifest/evaluator units pass and representative middleware/JIT tuning is planned |
| Typed target memory, thread, instrumentation, and lifecycle observations | The bounded worker and lifecycle path most recently passed at `085c8fe`; helper/schema/policy hostility is driver-free and skipped coverage remains explicit |
| Authoritative game movement, replay, and risk | Current driver-free tests pass canonical construction, hostile validation, replay rejection, sequence/tick gaps, movement/velocity bounds, server correction, coordinate extremes, and risk saturation; no production game workload is claimed |
| Renamed, signed normal post-start driver image | Most recently tested at `085c8fe`; armed callback and persistent latch both observed |
| Manual-map/kdmapper probe | Not covered by the checked-in VM test |
| HVCI/VBS enabled and disabled | Planned |
| Secure Boot production signing path | Planned |
| Maintained Windows 10 builds | Planned |
| Maintained Windows 11 builds beyond the recorded 26100 campaign | Planned |
| Corresponding supported Windows Server releases | Planned |
| x86, ARM64, Windows XP/historical releases | Unsupported |

The public README points to these maintainer records instead of embedding campaign bookkeeping.
Neither the current result nor historical campaigns provide universal Windows, hardware, HVCI/VBS,
or game-compatibility evidence.

## Hardening acceptance matrix

| Work package | Required evidence | State |
|---|---|---|
| WP-00 baseline/docs/tests | Debug/Release, pure units, schema/link checks, factual records | Local and VM-tested foundation; hosted CI required at merge |
| WP-01 production protocol | ABI/layout, negotiation, exact message types, hostile flags/sizes/payloads | Unit and driver-backed cases tested at `67d3f61` |
| WP-02 service/device identity | Standard-user status, admin direct-open denial, service open, IPC ACL, install/remove | Exercised acceptance tested at `67d3f61`; broader negative matrix remains |
| WP-03 per-file session | Claim, wrong file/process, cleanup/close, rundown race, tombstone, PID reuse, unload | Lifecycle, owner-exit, tombstone, race, and unload cases tested at `67d3f61`; literal numeric PID reuse remains unforced |
| WP-04 launch ticket | Success, mismatch, creator/path mismatch, expiry, cancel, replay | Hostile units and successful driver/service launch tested at `67d3f61` |
| WP-05 liveness | Launcher/service/target/handle exit order, job kill, idempotent revoke | Unit, crash, recovery, graceful-stop, child-process, and session-loss cases tested at `67d3f61` |
| WP-06 transport | Critical retention, overflow latch, acknowledgement, snapshot paging/stress | The accepted campaign's `663/663`, Debug/Release, PREfast, driver-backed runtime, and VM/Verifier gates passed at `67d3f61` |
| WP-07 scheduling | Event latency during slow scans, budgets, cancellation, thread resume | Driver-free budgets/metrics/resume, Clang-Tidy baseline, restricted-service metrics, and Driver Verifier passed at `67d3f61` |
| WP-08 policy | Stable rule decisions, deployment modes, signer classification, typed drift, display-text independence | The accepted campaign's Debug/Release `663/663`, static analysis, repository checks, and integrated VM/Verifier execution passed at `67d3f61` |
| WP-09 manifest authorization | Canonical serialization, signer/build scope, expiry, rollback, accepted launch | Driver-free, signed-package, production-boundary, and VM/Verifier acceptance passed at `67d3f61` |
| WP-10 signed policy | Wrong signature/scope, expiry, replay, equivocation, explicit rollback, emergency revoke, authenticated selection | Driver-free, signed-package, production-boundary, and VM/Verifier acceptance passed at `67d3f61` |
| WP-11 backend | Nonce replay, lease expiry/revocation, fixed queue, evidence acknowledgement, driver binding, protected mock, target-tree containment | Driver-free, restricted-service failure/recovery, production-boundary, and VM/Verifier acceptance passed at `67d3f61` |
| WP-12 scanner modularization | Coherent kernel scanner responsibilities, common user-mode ownership helpers, parser/helper units, no behavioral regression | Debug/Release `623/623`, driver PREfast, scanner Clang-Tidy, repository checks, VM/Verifier acceptance at `67d3f61`, and PR #18 hosted checks passed |
| WP-13 game/server integration | Canonical authoritative schema, exact identity/replay scope, hostile validation, one game invariant, server detector, and combined behavior/endpoint risk | Local and PR #19 hosted Debug/Release `663/663`, full builds, analysis, and repository checks passed at `8eca174`; no VM rerun was required for this portable-only change |
| WP-14 production release engineering | Signing/HLK plan, deterministic metadata, SPDX SBOM, symbol separation, update/rollback and key-rotation design, support, privacy, and runbooks | Source profile, exact unsigned candidate, schema and five hostile mutation checks pass locally; production certification/signing and deployed operations remain external promotion gates; hosted acceptance pending |
| WP-15 production endpoint trust | Correlated complete scan, frozen module inventory, driver trust/hash/family policy, signed runtime-module scope, typed target memory/thread/lifecycle findings, explicit degraded state, backend acknowledgement | Debug/Release `727/727`, full solution analysis, PREfast, complete service/client Clang-Tidy, repository validation, release-candidate hostility, exact signed package, and Windows 11/Driver Verifier acceptance passed at `974d2c4` |
| WP-16 production backend admission | Native mutual-TLS transport, exact certificate rotation, signed remote policy and crash-safe cache, durable lease/replay/evidence/game state, revocation/expiry/restart behavior, and typed game adapter | Managed Debug/Release `26/26`, real loopback mutual TLS, role separation, direct durable-restart tests, shared C/C++ protocol tests, and the exact Windows 11/Driver Verifier endpoint regression passed at `085c8fe`; hosted checks remain before merge |

WP-02 through WP-12 runtime acceptance is recorded only for the exact implementation commit and
environment above. PR #18 supplies the corresponding hosted build and repository-validation
evidence. PR #19 supplies WP-13's portable hosted build, unit, and repository-validation evidence.
WP-13 does not modify or extend the Windows runtime claim. WP-14 changes build metadata and
packaging boundaries rather than privileged runtime behavior. WP-15 runtime evidence applies only
to the exact `974d2c4` package and Windows 11 build 26100 campaign; it is not broader platform
certification.
WP-16 endpoint-regression evidence applies only to the exact `085c8fe` package and the same named
Windows build; the mutual-TLS backend evidence is from the managed loopback suite, not a claim of a
deployed production service.

## Exact host commands

```powershell
$oacVswhere = Join-Path ${env:ProgramFiles(x86)} `
  'Microsoft Visual Studio\Installer\vswhere.exe'
$oacVs = & $oacVswhere -latest -products * `
  -requires Microsoft.Component.MSBuild -property installationPath
$oacMsbuild = Join-Path $oacVs 'MSBuild\Current\Bin\amd64\MSBuild.exe'

foreach ($oacConfiguration in 'Debug', 'Release') {
  & $oacMsbuild .\OAC.sln /m /t:Rebuild `
    /p:Configuration=$oacConfiguration /p:Platform=x64 `
    /p:PreferredToolArchitecture=x64 /p:Inf2CatUseLocalTime=true
  if ($LASTEXITCODE -ne 0) { throw "$oacConfiguration build failed" }

  & ".\x64\$oacConfiguration\OAC-Protocol-Unit.exe"
  if ($LASTEXITCODE -ne 0) { throw "$oacConfiguration unit tests failed" }
}
```

Driver, protocol, callback, lifetime, synchronization, or IRQL changes additionally require the
complete driver-backed protocol test and Driver Verifier in a disposable VM. Record the Windows
build, security configuration, commands, exits, crash evidence, and Verifier cleanup; keep all raw
output outside the repository.
