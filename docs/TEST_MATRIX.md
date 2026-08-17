# OAC test matrix

**Status:** WP-01 through WP-04 test sources integrated; current disposable-VM acceptance pending

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
| `Debug|x64` solution build | Workflow matrix configured | Local passed with zero warnings/errors; final-commit CI pending |
| `Release|x64` solution build | Workflow matrix configured | Local passed with zero warnings/errors; final-commit CI pending |
| `OAC-Protocol-Unit.exe` | C/C++ driver-free unit project included in both configurations | Local Debug/Release passed `277/277`; final-commit CI pending |
| Protocol layout assertions | Diagnostic and production compile-time sizes/offsets | Compiled in both local configurations; final-commit CI pending |
| `InfVerif /w` | Required for package changes | Current local validation passed |
| PowerShell/Python/XML/YAML parse | Required repository checks | Current Windows PowerShell and PowerShell 7 validation passed |
| Clang-Tidy | Required for scanner changes | Historical result only |
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
- launch-ticket layouts, strict canonical NT paths, expiry/cancel/replay decisions, exact process
  handles, response correlation, and terminal state invariants; and
- launcher/service launch IPC layouts, hostile DOS paths, reserved fields, dirty tails, and success
  or rejection identity invariants.

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
  with `ERROR_BUSY`, and permits reclaim only after the target exits; and
- after a production-session owner exits, a wrong-process holder of the exact old file object remains denied while
  a different file immediately claims a distinct, higher-generation session; and
- malformed launch requests are rejected while diagnostic sessions receive `ERROR_NOT_SUPPORTED`
  for production arm, cancel, and confirm operations.

These tests exercise real file contexts, authorization, and rundown. Their current VM execution and
Driver Verifier results are pending. Driver-free tests cover the launch wire contract, canonical
path rejection, expiry boundary, creator/path decision matrix, cancellation, exact handle fields,
and terminal state transitions. The VM production boundary exercises the real creation callback and
service-owned launch; alert acknowledgement and snapshot paging remain later work.

## Service and launcher coverage

The VM harness source now contains a bounded `LabMode=0` production-boundary phase that:

- starts the restricted `OACService` and requires its production claim;
- runs standard-user launcher status twice;
- attempts direct driver opens as LocalSystem, a limited user, and an administrator and requires all
  three to fail;
- launches `whoami.exe` as the standard user, requires exact creation-time binding and process-handle
  confirmation, and accepts success only after the initial thread is resumed;
- stops the service and restores explicit lab mode before diagnostic tests;
- records cleanup separately so a failed boundary test cannot silently leave the wrong mode active.

The installer structurally reads back the service type, manual start, LocalSystem account, OAC
dependency, restricted service SID type, exact four-privilege list, fixed SID, binary paths, SYSTEM
owner/group, and exact query-status/start-only Administrators and Interactive ACL. It also verifies
a one-day reset policy with one restart after five seconds followed by no further action, including
non-crash failures. A targeted LocalSystem native-policy probe passed on Windows 11 24H2 build
26100. Full installer, effective service-right, reboot-persistence, and production-boundary VM
acceptance remain pending.

## Runtime matrix

| Environment or scenario | Evidence |
|---|---|
| Windows 11 Pro 24H2 build 26100, networkless Hyper-V, test signing | Historical for the diagnostic protocol; current production run pending |
| Standard Driver Verifier on `OAC.sys` | Historical for earlier source; current session/rundown run pending |
| Production service identity, device ACL, standard-user launcher, admin direct-open denial | Source present; current VM run pending |
| SCM owner/DACL effective rights and recovery persistence | Structural native-policy probe passed on build 26100; negative-right and reboot tests pending |
| Production per-file cleanup/close and concurrent status teardown | Source present; current VM run pending |
| Live-target tombstone and later retirement | Source and driver-backed test present; current VM result pending |
| Standard-user service launch, creation-time binding, confirmation, and resume | Source and VM harness present; current VM result pending |
| Renamed, signed normal post-start driver image | Historical load-latch evidence; current rerun pending |
| Manual-map/kdmapper probe | Not covered by the checked-in VM test |
| HVCI/VBS enabled and disabled | Planned |
| Secure Boot production signing path | Planned |
| Maintained Windows 10 builds | Planned |
| Maintained Windows 11 builds beyond the recorded 26100 campaign | Planned |
| Corresponding supported Windows Server releases | Planned |
| x86, ARM64, Windows XP/historical releases | Unsupported |

Historical results are summarized in the root README. They must not be used as acceptance evidence
for the current service/session source.

## Hardening acceptance matrix

| Work package | Required evidence | State |
|---|---|---|
| WP-00 baseline/docs/tests | Debug/Release, pure units, schema/link checks, factual records | Source and workflow present; final results pending |
| WP-01 production protocol | ABI/layout, negotiation, exact message types, hostile flags/sizes/payloads | Source and unit coverage present; final host/VM results pending |
| WP-02 service/device identity | Standard-user status, admin direct-open denial, service open, IPC ACL, install/remove | Source and VM harness present; VM result pending |
| WP-03 per-file session | Claim, wrong file/process, cleanup/close, rundown race, tombstone, PID reuse, unload | Source and driver-backed harness present; current VM result pending |
| WP-04 launch ticket | Success, mismatch, creator/path mismatch, expiry, cancel, replay | Driver/service/launcher source, hostile units, and VM acceptance source present; current driver-backed result pending |
| WP-05 liveness | Launcher/service/target/handle exit order, job kill, idempotent revoke | Planned |
| WP-06 transport | Critical retention, overflow latch, acknowledgement, snapshot paging/stress | Planned |
| WP-07 scheduling | Event latency during slow scans, budgets, cancellation, thread resume | Planned |
| WP-08 policy | Stable rule decisions, corroboration, display-text independence | Planned |
| WP-09/10 signatures | Wrong key/scope/build, expiry, rollback, canonical serialization | Planned |
| WP-11 backend | Nonce replay, lease expiry, evidence acknowledgement, offline mock | Planned |

WP-02 and WP-03 are not complete until their disposable-VM acceptance evidence is recorded.

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
