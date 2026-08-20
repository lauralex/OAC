# OAC test matrix

**Status:** WP-01 through WP-10 tested at acceptance commit
`865a9f9b5d665c1c69fcf8b39486722046d6647f` on Windows 11 build 26100. WP-11
backend-session source and tests are present; current VM acceptance is pending.

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
| `Debug|x64` solution build | Workflow matrix configured | Local and PR #13 hosted builds passed with zero warnings/errors |
| `Release|x64` solution build | Workflow matrix configured | Local and PR #13 hosted builds passed with zero warnings/errors |
| `OAC-Protocol-Unit.exe` | C/C++ driver-free unit project included in both configurations | Current local Debug/Release runs passed `608/608`; PR #13 previously passed `428/428` |
| Protocol layout assertions | Diagnostic and production compile-time sizes/offsets | Compiled in both local configurations and on PR #13 |
| `InfVerif /w` | Required for package changes | Current local validation passed |
| PowerShell/Python/XML/YAML parse | Required repository checks | Current Windows PowerShell and PowerShell 7 validation passed |
| Clang-Tidy | Required for scanner changes | Service and diagnostic scanner projects passed with warnings treated as errors at the accepted WP-07 baseline; WP-11 changes no scanner source |
| Driver PREfast | Required for driver/lifetime changes | Current local `DriverMinimumRules` run passed with zero warnings/errors |
| Secret scan | GitGuardian branch check configured | Required repository check |

The workflow builds Debug and Release, runs
`x64/<Configuration>/OAC-Protocol-Unit.exe`, uploads unsigned Release artifacts without PDBs, and
keeps the stable aggregate job name `build`. A green hosted workflow is compile and pure-unit
evidence; it does not load the driver or test Windows service security.

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
- backend open, renewal, evidence, and acknowledgement layouts; strict size/type/session/nonce/time
  correlation; replay-window bounds; sequence and acknowledgement monotonicity; fixed-queue and
  timeout outcomes; binding digest; mock restart; lease expiry; and revocation; and
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
standard Driver Verifier run passed on acceptance commit `865a9f9b5d665c1c69fcf8b39486722046d6647f`.
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
| Windows 11 Pro 24H2 build 26100, networkless Hyper-V, test signing | Tested at `865a9f9`; 40 exact results, overall pass, Secure Boot disabled |
| Standard Driver Verifier on `OAC.sys` | Tested at `865a9f9`; three loads/unloads, reset and inactive at completion, zero crashes/dumps |
| Production service identity, device ACL, standard-user launcher, admin direct-open denial | Tested at `865a9f9`; status four times, launch twice, and LocalSystem/limited/admin direct opens denied |
| SCM owner/DACL effective rights and recovery persistence | Structural native-policy probe passed on build 26100; negative-right and reboot tests pending |
| Production per-file cleanup/close and concurrent status teardown | Tested at `865a9f9` in baseline and Verifier protocol executions |
| Live-target tombstone and later retirement | Tested at `865a9f9` in the driver-backed lifecycle suite |
| Standard-user service launch, creation-time binding, confirmation, job assignment, and resume | Tested twice at `865a9f9` |
| Service-owned job, parent/child termination, crash recovery, graceful revoke | Tested at `865a9f9`; both process trees terminated and SCM recovery completed |
| Retained alerts, event gaps, overflow provenance, concurrent publication, paged snapshots | Tested at `865a9f9`; four driver-backed executions passed `130/130` |
| Independent health loop and bounded target worker | Tested at `865a9f9`; 38 slices, eight sweeps, 313 ms maximum health delay, 151.377 ms maximum slice duration, 36.533 ms maximum suspension, no failed/cancelled slice |
| Typed policy rules and service evaluation | Current driver-free tests pass `608/608`; integrated signed-policy service execution passed at `865a9f9` |
| Signed main-executable manifest authorization | Tested at `865a9f9`; two authorized launches passed and modified, wrong-build, expired, and rollback manifests were rejected |
| Signed policy selection and update state | Tested at `865a9f9`; signer, scope, expiry, rollback, authorized rollback, and emergency-revocation cases passed |
| Backend session, lease, replay, and acknowledgement failure | Source and driver-free tests present; commit-bound VM/Verifier execution pending |
| Renamed, signed normal post-start driver image | Tested at `865a9f9`; armed callback and persistent latch both observed |
| Manual-map/kdmapper probe | Not covered by the checked-in VM test |
| HVCI/VBS enabled and disabled | Planned |
| Secure Boot production signing path | Planned |
| Maintained Windows 10 builds | Planned |
| Maintained Windows 11 builds beyond the recorded 26100 campaign | Planned |
| Corresponding supported Windows Server releases | Planned |
| x86, ARM64, Windows XP/historical releases | Unsupported |

The root README separates this current exact-commit result from older historical campaigns. Neither
is universal Windows, hardware, HVCI/VBS, or game-compatibility evidence.

## Hardening acceptance matrix

| Work package | Required evidence | State |
|---|---|---|
| WP-00 baseline/docs/tests | Debug/Release, pure units, schema/link checks, factual records | Local and VM-tested foundation; hosted CI required at merge |
| WP-01 production protocol | ABI/layout, negotiation, exact message types, hostile flags/sizes/payloads | Unit and driver-backed cases tested at `865a9f9` |
| WP-02 service/device identity | Standard-user status, admin direct-open denial, service open, IPC ACL, install/remove | Exercised acceptance tested at `865a9f9`; broader negative matrix remains |
| WP-03 per-file session | Claim, wrong file/process, cleanup/close, rundown race, tombstone, PID reuse, unload | Lifecycle, owner-exit, tombstone, race, and unload cases tested at `865a9f9`; literal numeric PID reuse remains unforced |
| WP-04 launch ticket | Success, mismatch, creator/path mismatch, expiry, cancel, replay | Hostile units and successful driver/service launch tested at `865a9f9` |
| WP-05 liveness | Launcher/service/target/handle exit order, job kill, idempotent revoke | Unit, crash, recovery, graceful-stop, child-process, and session-loss cases tested at `865a9f9` |
| WP-06 transport | Critical retention, overflow latch, acknowledgement, snapshot paging/stress | Current `608/608`, Debug/Release, PREfast, driver-backed `130/130`, and VM/Verifier acceptance passed at `865a9f9` |
| WP-07 scheduling | Event latency during slow scans, budgets, cancellation, thread resume | Driver-free budgets/metrics/resume, Clang-Tidy, restricted-service metrics, and Driver Verifier passed at `865a9f9` |
| WP-08 policy | Stable rule decisions, deployment modes, signer classification, typed drift, display-text independence | Debug/Release `608/608`, static analysis, repository checks, and integrated VM/Verifier execution passed at `865a9f9` |
| WP-09 manifest authorization | Canonical serialization, signer/build scope, expiry, rollback, accepted launch | Driver-free, signed-package, production-boundary, and VM/Verifier acceptance passed at `865a9f9` |
| WP-10 signed policy | Wrong signature/scope, expiry, replay, equivocation, explicit rollback, emergency revoke, authenticated selection | Driver-free, signed-package, production-boundary, and VM/Verifier acceptance passed at `865a9f9` |
| WP-11 backend | Nonce replay, lease expiry/revocation, fixed queue, evidence acknowledgement, driver binding, protected mock, target-tree containment | Source and driver-free tests present; VM/Verifier acceptance pending |

WP-02 through WP-10 acceptance is recorded only for the exact commit and environment above. WP-11
remains source-present until its named campaign completes.

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
