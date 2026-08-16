# OAC test matrix

**Status:** WP-01 through WP-03 test sources integrated; current disposable-VM acceptance pending

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
| `Debug|x64` solution build | Workflow matrix configured | Final branch result pending |
| `Release|x64` solution build | Workflow matrix configured | Frozen baseline Release was tested; current result pending |
| `OAC-Protocol-Unit.exe` | C/C++ driver-free unit project included in both configurations | Final local/CI result pending |
| Protocol layout assertions | V4 and v5 compile-time sizes/offsets | Compiled result pending final build |
| `InfVerif /w` | Required for package changes | Frozen baseline passed; current rerun pending |
| PowerShell/Python/XML/YAML parse | Required repository checks | Frozen baseline passed; current rerun pending |
| Clang-Tidy | Required for scanner changes | Historical result only |
| PREfast/MSVC analysis | Required for driver/lifetime changes | Current rerun pending |
| Secret scan | GitGuardian branch check configured | Required repository check |

The workflow builds Debug and Release, runs
`x64/<Configuration>/OAC-Protocol-Unit.exe`, uploads unsigned Release artifacts without PDBs, and
keeps the stable aggregate job name `build`. A green hosted workflow is compile and pure-unit
evidence; it does not load the driver or test Windows service security.

### Driver-free v5 coverage

The pure C/C++ unit source covers:

- C and C++ ABI compatibility, structure sizes/offsets, distinct IOCTLs, buffered transfer, and
  read/write access bits;
- exact `MessageType`/IOCTL matching and request/response correlation;
- strict version, length, ID, session, generation, flag, reserved, range, and alignment checks;
- negotiation, claim, and status requests and responses, including revoked-state consistency;
- stable rule/event IDs, severity, confidence, category, and the exact session transition matrix;
- event provenance rules and hostile none, binary, and UTF-16 payload cases, including dirty tails,
  embedded nulls, and invalid surrogate pairs.

This validates the schema and pure validators, not the kernel dispatcher or service boundary.

## Driver-backed protocol coverage

`OAC-Protocol-Test.exe` requires an installed, running test-signed driver in an isolated disposable
VM. Its current source includes the earlier v4 malformed-request, scan, CPU, finding, and driver-gate
coverage plus these v5 cases:

- claim denied before negotiation and production claim denied to a lab administrator;
- exact negotiation/claim/status correlation and malformed version, size, request ID, flags,
  `MessageType`, session, generation, mode, and reserved fields;
- bidirectional per-file exclusion between v5 negotiation/claim and privileged v4 operations;
- a second file may negotiate but cannot claim or use copied session credentials;
- a duplicated handle used from another process cannot use the owning file's session;
- cleanup/close removes authority and a replacement claim receives a different session ID and
  higher generation;
- four concurrent status workers each complete 32 valid warm-up requests, then race one final
  request with handle cleanup; completions must be valid or fail with a bounded close result;
- a replacement claim after the race advances generation;
- closing the controller with a live v4 target leaves a tombstone, rejects a replacement claim
  with `ERROR_BUSY`, and permits reclaim only after the target exits; and
- after a v5 owner exits, a wrong-process holder of the exact old file object remains denied while
  a different file immediately claims a distinct, higher-generation session.

These tests exercise real file contexts, authorization, and rundown. Their current VM execution and
Driver Verifier results are pending. The suite does not yet exercise a creation-time launch ticket,
production target binding, alert acknowledgement, or snapshot paging.

## Service and launcher coverage

The VM harness source now contains a bounded `LabMode=0` production-boundary phase that:

- starts the restricted `OACService` and requires its v5 production claim;
- runs standard-user launcher status twice;
- attempts direct driver opens as a limited user and as an administrator and requires both to fail;
- stops the service and restores explicit lab mode before diagnostic tests;
- records cleanup separately so a failed boundary test cannot silently leave the wrong mode active.

The installer also verifies the service type, manual start, LocalSystem account, OAC dependency,
restricted service SID type, required privilege list, fixed SID, binary paths, and protected ACLs.
Source coverage is present; its current VM result is pending.

## Runtime matrix

| Environment or scenario | Evidence |
|---|---|
| Windows 11 Pro 24H2 build 26100, networkless Hyper-V, test signing | Historical for protocol v4; current v5 run pending |
| Standard Driver Verifier on `OAC.sys` | Historical for earlier source; current session/rundown run pending |
| V5 service identity, device ACL, standard-user launcher, admin direct-open denial | Source present; current VM run pending |
| V5 per-file cleanup/close and concurrent status teardown | Source present; current VM run pending |
| Live-target tombstone and later retirement | Source and driver-backed test present; current VM result pending |
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
| WP-01 protocol v5 | ABI/layout, negotiation, exact message types, hostile flags/sizes/payloads | Source and unit coverage present; final host/VM results pending |
| WP-02 service/device identity | Standard-user status, admin direct-open denial, service open, IPC ACL, install/remove | Source and VM harness present; VM result pending |
| WP-03 per-file session | Claim, wrong file/process, cleanup/close, rundown race, tombstone, PID reuse, unload | Source and driver-backed harness present; current VM result pending |
| WP-04 launch ticket | Success, mismatch, creator/path mismatch, expiry, cancel, replay | Planned |
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
