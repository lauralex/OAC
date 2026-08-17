# OAC

OAC is a defensive, x64 Windows anti-cheat reference implementation. Its production control
foundation consists of an unsigned-by-default, demand-start kernel driver, a restricted
`OACService`, a standard-user launcher, and a typed protocol-v5 session bound to one file object and
one referenced service process. The current service surface deliberately exposes only
access-controlled, identity-checked health/status IPC; creation-time launch tickets and target
liveness are the next work packages, so this revision is not yet a complete production
anti-cheat.

The existing protocol-v4 scanner remains available only when the disposable-VM/lab `LabMode`
registry switch is explicit. `OAC-Client` keeps one diagnostic handle for its entire run and refuses
to act as a production controller. The kernel component performs bounded, IRQL-appropriate work;
pageable inspection, signature validation, reporting, and stack walking stay in user mode. The
driver is always `SERVICE_DEMAND_START`, never boot-start.

## Project guide

- [`AGENTS.md`](AGENTS.md) is the concise repository guide for coding agents and maintainers.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) describes development and review requirements.
- [`SECURITY.md`](SECURITY.md) explains private vulnerability reporting and sensitive-data rules.
- [`docs/README.md`](docs/README.md) indexes current procedures, research notes, and the explicitly
  planned [`production hardening roadmap`](docs/hardening-plan.md).

The production driver currently implements protocol-v5 negotiate, claim, and status requests and
advertises only session control. The shared v5 header also defines the typed event schema and IDs
reserved for later transport work; their presence is not a claim that event delivery, scanning,
launch tickets, or revocation requests are available through v5 yet. Source-level WP-01 through
WP-03 foundations are integrated, but their current disposable-VM acceptance run is still pending.

## Security and compatibility contract

- The maintained design target is **x64 Windows 10, Windows 11, and corresponding Windows Server
  releases**. The portable path is not keyed to a Windows build number and is intended to remain
  active across every patched build in that maintained family. Stable checks use documented APIs
  or length-validated system-information responses.
- Newer optional APIs (`ExAllocatePool2`, `MmCopyMemory`, catalog SHA-256 helpers, and
  `PsGetProcessDebugPort`/`PsGetProcessExitStatus`) are resolved dynamically and have older
  fallbacks.
- Private kernel data is never a load or protection dependency. A private check runs only when
  the running kernel exactly matches a reviewed IDALib profile; otherwise OAC reports the skipped
  capability and continues with stable cross-view heuristics.
- Production authority requires the exact `OACService` SID, the CREATE-owner process object, the
  claimed file object, a random 128-bit session ID, and a nonzero generation. Cleanup revokes the
  file session, and a live diagnostic target leaves a tombstone that prevents unsafe reclamation.
  Numeric PIDs are diagnostics only. Administrators retain direct access only in explicit lab mode.
- Protocol authority cannot be mixed on one file: v5 negotiation excludes privileged v4 calls, and
  a v4 diagnostic claim prevents later v5 negotiation.
- A single binary cannot safely cover every historical Windows release and architecture. Windows
  XP lacks the object callbacks required for handle filtering, and x86/ARM64 require different
  context, register, PE, and calling-convention implementations. OAC fails or degrades explicitly
  instead of guessing a structure offset.
- `ObRegisterCallbacks` filters user-mode process and thread handles. It cannot stop a hostile
  kernel driver, DMA device, hypervisor, or already-compromised kernel. “Block all interaction” is
  therefore implemented as the strongest supported user-mode handle policy, with the protected
  process and current OAC controller allowlisted.

## Lab scanner capability coverage

The table below describes the protocol-v4 diagnostic scanner available only with `LabMode=1`. The
status-only production service does not expose these scan operations yet.

| Capability | Implementation |
|---|---|
| Block interaction with the game / handle creation | Signed `ObRegisterCallbacks` process and thread create/duplicate filtering strips terminate, injection, VM, context, duplication, and suspension rights. Existing handles are inventoried and reported. |
| Hidden processes | Toolhelp, PSAPI, and `NtQuerySystemInformation` cross-view in the client; kernel process snapshot is compared with handle/object owners. Live-process revalidation reduces process-churn false positives. |
| Hidden kernel modules | `AuxKlibQueryModuleInformation` versus system-module cross-view, load-image telemetry, IDT/LSTAR validation, and system-thread start addresses outside all modules. |
| Suspicious DLLs | Three-view module inventory plus explicit cheat/injector IOCs and separately classified overlay/hooking modules. |
| Suspicious drivers / all loaded drivers | Kernel and PSAPI inventories, a shared conservative family deny/review policy, 542 compiled exact Authenticode SHA-256 denies, embedded-or-catalog trust validation, and individual inventory records when driver paths can be resolved. Unresolved paths are counted and reported in aggregate. A monotonic callback-era load latch survives random names, rapid unload, file deletion, telemetry draining, and PiDDB/hash/unloaded-driver trace cleanup. The compiled policy and latch operate even when the host HVCI or Microsoft blocklist settings are off. |
| All open handles | Extended system-handle snapshot saved to `oac-open-handles.csv`; target handles are correlated by kernel object identity. |
| Disks and devices | Logical volumes, DOS device names, physical-drive storage descriptors, and all present PnP devices. |
| HWID | Multi-source, privacy-preserving identity graph: bounded SMBIOS types, Windows-computed hardware-ID registry corroboration, storage descriptors/IDs/DUID/FRU/NVMe/ATA, GPT/MBR and mount-manager IDs, PnP instances/containers, permanent/current NIC addresses, EDID, battery-class serial/unique IDs, HID/Bluetooth, and ACPI. Placeholders are rejected, comparable paths are cross-checked after format normalization, removable evidence is separated from stable core anchors, and raw material is not written to the report. |
| Debuggers | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, three native process debug classes, dynamically resolved kernel `PsGetProcessDebugPort`, kernel debugger globals, DR6, and DR7. |
| Manually mapped drivers and traces | A single current-state snapshot checks system-thread start addresses and kernel control-flow targets outside loader modules, plus `MmUnloadedDrivers` and PiDDB where an exact profile exists. In addition, every normal helper-driver load after OAC starts permanently trips a fail-closed latch, even if a mapper immediately unloads the helper and cleans loader traces. A before-state snapshot is not required. |
| Kernel patches and hooks | Per-processor CR0/CR4/EFER, syscall MSRs, IDTR/GDTR and IDT-gate ownership; bounded ntoskrnl/OAC IAT target checks; selected kernel export baseline/prologue checks; OAC dispatch-table/self-image validation; and loader-backed user IAT/export checks. The IPI callback only copies register/descriptor metadata; analysis occurs later at PASSIVE_LEVEL. Findings are targeted integrity heuristics, not a replacement for PatchGuard/HVCI. |
| Physical-memory handles | Kernel object-identity comparison against `\\Device\\PhysicalMemory`. |
| Modules using `VirtualProtect` | Remote PE import parsing for `VirtualProtect`, `VirtualProtectEx`, and `NtProtectVirtualMemory`. |
| Strings in unbacked regions | Bounded reads of executable non-image regions, suspect printable-string context, and `oac-suspect-strings-<pid>.txt`. |
| Syscall stubs in unbacked regions | Direct x64 syscall-stub pattern scan in executable non-image memory. |
| Overlay windows | Target-window intersection against visible topmost, layered, transparent, and no-activate windows owned by other processes. |
| Suspicious shared sections | Executable `MEM_MAPPED` regions, mapped-path resolution, and writable-executable classification. |
| Services | All Win32 and driver services are checked and saved to `oac-services.csv`; suspicious service/path IOCs are elevated. |
| All threads and system threads | Every target thread is enumerated; kernel System-process thread starts are checked against loaded-driver ranges. |
| Stack walking | Target threads are briefly suspended with guaranteed resume and walked through `StackWalk64`; executable frames outside modules are reported. No unwinding occurs in NMI/high-IRQL context. |
| Manually mapped user modules | Executable `MEM_PRIVATE` regions, PE validation, memory-image/Toolhelp/PSAPI cross-view, thread starts, and stack frames. |
| Turla Driver Loader | `VBoxDrv` driver/service/device IOCs, `VBoxDrv.backup`, loaded-driver state, and out-of-module system execution. A normal current VirtualBox installation is not treated as conclusive by itself. |
| Hypervisor / VM | Repeated user/kernel CPUID namespace checks, per-CPU consistency, firmware indicators, Secure Boot, VBS/Device Guard/HVCI state, code-integrity options, kernel-debugger state, and contradiction reporting. Hyper-V/VBS is reported separately rather than automatically labeled malicious. Timing is weak telemetry only and is never a standalone verdict. |
| `DbgUiRemoteBreakin` patch | Opt-in `--apply-hardening` writes a one-byte `RET`, restores page protection, and flushes the instruction cache. |
| HideFromDebugger | Opt-in `ThreadHideFromDebugger` on each accessible target thread. |
| Instrumentation callbacks | Native `ProcessInstrumentationCallback` query and module-range validation. |
| CPU register sampling | Per-processor IPI callback captures CR0/3/4, DR0-3/6/7, EFER, LSTAR/CSTAR/STAR/FMASK, SYSENTER, IDTR/GDTR, CPUID namespaces, and TSC_AUX into a dynamically sized, nonpaged response; no fixed CPU-count array is used. Processor hot-add/removal cannot cause an out-of-bounds record. |

OAC correlates independent observations and preserves uncertainty. It does not promise detection of
every anomaly: a malicious driver executing at kernel privilege can forge kernel observations, and
a hostile hypervisor can forge every guest-visible observation. Production enforcement therefore
also needs server-side behavioral analysis, signed policy/allowlists, revocation, measured boot or
attestation where available, and a supported hardware/OS matrix.

## Build

Requirements:

- Visual Studio 2022 with the Desktop C++ workload
- Windows SDK and WDK 10.0.26100 or newer
- x64 configuration

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe" `
  OAC.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

Use the 64-bit MSBuild host shown above with the x64 WDK toolchain. The build stages the INF,
driver, and generated catalog under `x64\Release\OAC`, and builds `OAC-Service`, `OAC-Launcher`,
the lab compatibility client, the driver-backed protocol test, and the driver-free protocol unit
test under `x64\Release`. The catalog and driver still require an authorized signature before
installation.

The repository build intentionally produces an unsigned `OAC.sys`; it does not generate or trust
an ad-hoc certificate. Sign the binary/package through your organization's test or production
driver-signing pipeline before loading it. Windows requires x64 kernel drivers to be signed, and
`ObRegisterCallbacks` returns `STATUS_ACCESS_DENIED` when callback code is not in a signed kernel
image. The driver is linked with `/INTEGRITYCHECK`, which is also required for the extended process
notification callback. Production releases should use Microsoft Hardware Dev Center signing/HLK
as applicable.
Set `OAC_OB_ALTITUDE` to the collision-free callback altitude assigned to the production build;
the checked-in value is only a development default, and registration fails safely on a collision.
The client uses the static Visual C++ runtime so the scanner does not acquire a separate UCRT
redistributable dependency.

Do **not** use a vulnerable-driver mapper or turn off HVCI, the Microsoft blocklist, or Secure Boot
merely to run OAC. OAC's own gate does not require those controls, but it treats them as useful
defense-in-depth telemetry when they are present.

## Run

Install the properly signed `OAC` driver and `OACService` through reviewed deployment tooling. Both
remain demand-start; do not configure either as boot-start, system-start, or automatic-start. A
standard user can verify the production control path without receiving a driver handle:

```powershell
OAC-Launcher.exe --status
```

The current service intentionally does not launch a game. Launch requests remain unavailable until
the creation-time ticket and liveness work packages are implemented and tested.

The following direct scanner flows are lab-only. They require `LabMode=1`, must not be enabled on a
production machine, and use `audit` or `test` deployment mode.

Global preflight without creating a game:

```powershell
OAC-Client.exe --preflight --mode test --output .\scan-output
```

Legacy suspended diagnostic launch flow:

```powershell
OAC-Client.exe --launch "C:\Games\Example\Game.exe" `
  --launch-args "-example" `
  --mode test `
  --challenge 00112233445566778899AABBCCDDEEFF `
  --output .\scan-output
```

Attach to an already running test process and continue monitoring:

```powershell
OAC-Client.exe --pid 1234 --monitor --mode test --output .\scan-output
```

Optional switches:

- `--apply-hardening`: mutates the target by patching `DbgUiRemoteBreakin` and applying
  `ThreadHideFromDebugger`.
- `--preflight`: performs the complete global gate with no protected target.
- `--launch <path>`: creates the target suspended and implies `--monitor`; `--launch-args` supplies
  its arguments.
- `--monitor`: keeps the trusted client and kernel protection identity alive, polls the persistent
  driver-load latch every 250 ms by default, drains image-load events, checks current loaded-driver
  hashes every two seconds, repeats kernel scans every 15 seconds, and repeats target scans every
  30 seconds.
- `--monitor-interval-ms`: sets the event-drain interval from 250 to 60000 ms.
- `--verbose-handles`: asks the kernel to emit individual handle records; this can overflow the
  bounded telemetry ring on busy machines. The client CSV always contains the raw full inventory.
- `--no-private-kernel-traces`: disables IDALib-profiled PiDDB and unloaded-driver inspection.
- `--mode audit|test`: selects lab policy. `OAC-Client` refuses direct production authority; use
  the service/launcher path for production-control development.
- `--fail-on low|medium|high|critical`: controls the exit-code enforcement threshold.
- `--require-hvci`: treats inactive HVCI as a policy failure.
- `--challenge <hex>`: binds the lab report chain to a supplied 16-64 byte nonce. This does not
  authenticate the scanner; the production backend challenge and upload path is not implemented.

The lab client exits `0` when no finding reaches the configured threshold, `1` when actionable
findings are present, and a larger value for argument, scan, or report failures. Reports use a
per-run ID,
sequence/timestamped SHA-256 finding chain, inventory-artifact digests, an atomic replace, and a
`.sha256` sidecar. Those unkeyed hashes expose accidental or after-the-fact tampering; they do not
authenticate the scanner. Production deployments must combine the challenge with authenticated,
prompt server upload and reject reused or expired nonces. Heuristics require an allowlist for the
specific game, overlays, accessibility tools, endpoint security, and virtualization configuration.

### Independent vulnerable-driver policy

`OAC-Client\driver_hash_policy.inc` is a compiled runtime snapshot, so OAC does not depend on the
host's Microsoft vulnerable-driver blocklist toggle or on HVCI. The checked-in snapshot contains
542 full Authenticode SHA-256 deny hashes from Microsoft policy version `10.0.29545.0`, archive
SHA-256 `381E9C886C6F1B1EAFE23597D5D92A538E69AC26F031F96AE07433ACDAE82B43`.
Regeneration is deliberately hash-pinned:

```powershell
.\tools\Update-OACDriverPolicy.ps1 `
  -ExpectedZipSha256 381E9C886C6F1B1EAFE23597D5D92A538E69AC26F031F96AE07433ACDAE82B43
```

For an already-reviewed offline archive, add `-SourceArchivePath <zip>`; the same expected hash is
still mandatory.

Review the upstream policy diff and test compatibility before accepting a new archive hash. Exact
hash rules are supplemented by OAC-owned conservative basename rules shared with the kernel image
telemetry path. A renamed helper cannot evade the monotonic post-start load latch, and a manually
mapped payload is handled by loader-independent execution and control-flow checks rather than by
its filename. Because the public image callback is observational, the lab path can fail its gate or
revoke its diagnostic target after the latch is observed; OAC does not claim that it can
retroactively prevent a payload's already-entered `DriverEntry`. Production launch enforcement is
planned with the launch-ticket and liveness work packages.

## Disposable-VM test signing

The repository includes a gated local test-package workflow. It is for disposable Windows test VMs
only and is not a production signing path. On the build machine:

```powershell
.\tools\New-OACTestPackage.ps1 -Configuration Debug
```

The script creates a 30-day RSA-3072 certificate named `OAC LOCAL TEST ONLY - NOT FOR PRODUCTION`,
signs the driver package and user-mode binaries, verifies their signatures, hashes both protocol
tests, writes a manifest, deletes the exact temporary CurrentUser `My` certificate and private key,
and scrubs the exact incidental CurrentUser `CA` cache entry. Its default output is a timestamped
directory under the system temporary directory, outside the source tree. Copy the printed result
directory to a disposable VM and run a 64-bit elevated terminal there to enable test-signing mode:

```powershell
.\Install-OACTestDriver.ps1 `
  -PackageDirectory .\package `
  -EnableTestSigning `
  -ConfirmDisposableVm
```

Reboot when `bcdedit` requests it. The actual install and removal paths require a LocalSystem
PowerShell process inside the disposable VM; the automated harness supplies that boundary, while a
manual lab must use its trusted provisioning mechanism. Rerun without `-EnableTestSigning` to
install/start the driver and optionally pass `-SmokeTestPid <pid>`. Windows normally requires Secure
Boot to be disabled before test-signing mode can be enabled; the installer deliberately refuses to
automate that firmware change. Never use this package on a production machine, export or distribute
its private key, or ship a binary trusted only by this local certificate. See
[the test-signing guide](docs/test-signing.md) for the exact containment and cleanup procedure.

## IDALib profiles and kernel-load research

Analysis was performed on hash-verified copies in an isolated temporary directory, never on live
system binaries in place. For the reviewed `ntoskrnl.exe` 10.0.22621.7376 image, PDB-backed IDALib
analysis confirmed exported API availability and the exact-build private RVAs used by the optional
trace profile. It also confirmed that a tempting PiDDB lock signature lives in discarded `INIT`
code; the runtime scanner therefore uses only exact-profile data RVAs and never scans discarded
kernel sections.

The profile is intentionally inert on a different timestamp, image size, or checksum. Add a new
profile only after repeating symbol-backed analysis and testing on that exact Windows build.

A second safe-copy review traced the normal demand-load path on `ntoskrnl.exe` 10.0.22621.7517
(SHA-256 `84F859B4987B24A30948D7139117146A9C658486E9271B7037CFFB1CE756C3A6`) and
`ci.dll` 10.0.22621.5185 (SHA-256
`747ACF8BD77FBBEDAC645675A9FE637C9A2CACD29F524EC11D0C4A6F923347DF`). It confirmed that the
real veto occurs in private Code Integrity image validation before `DriverEntry`, while the public
load-image callback is post-map notification. OAC therefore does not patch CI or hook private
loader functions; it fails closed at the protected-session boundary. See
[the kernel driver-load review](docs/driver-load-review.md).

The separate [hardware identity review](docs/hwid-review.md) records the hash-verified
30-driver corpus, the supported identity paths confirmed by each storage/USB/network/display/battery
component, and the privacy and stability rules applied by the collector.

## Validation evidence

For the current WP-01 through WP-03 source, the repository workflow is configured to build Debug
and Release and run the driver-free protocol unit executable. A current disposable-VM run of the
v5 service, device ACL, per-file lifecycle, cleanup race, protocol integration suite, and Driver
Verifier is still pending. Do not reuse the results below as evidence for those changes.

The following evidence is historical and predates the current v5 service/session foundation:

- Clean x64 Debug and Release rebuilds with MSVC `/W4`, SDL checks, and warnings as errors.
- x64 MSVC/PREfast code analysis for both the driver and client, plus user-mode Clang static
  analysis with the analyzer, bug-prone, performance, and portability check families enabled and
  diagnostics treated as errors. The checked-in policy excludes only known non-actionable Win32
  remote-address casts, similar-parameter API-shape advice, and an MSVC STL enum false positive.
- `InfVerif /w` validation of `OAC.inf`, WDK package signability/catalog generation, and XML
  parsing of every project and filter file.
- PE inspection of the Release artifacts: the driver has x64, ASLR, NX, CFG, and
  `/INTEGRITYCHECK`; optional newer kernel APIs are not static imports. The client embeds its
  administrator manifest and has no Visual C++ runtime DLL dependency.
- A locally generated disposable-VM package completed SYS/catalog digest-and-signer verification
  and independent manifest-hash verification. Its private key was non-exportable, the host trust
  stores were not modified, and the exact temporary certificate was absent from CurrentUser `My`
  afterward.
- An isolated, networkless Hyper-V Generation 2 VM running Windows 11 Pro 24H2 build 26100 loaded
  the test-signed demand-start driver and completed four protocol tests plus seven client gates at a
  `medium` failure threshold. Baseline and standard Driver Verifier phases completed without an
  unexpected restart, minidump, bugcheck, nonzero test exit, fatal result, or verifier state left
  enabled; the durable guest result reported `overall_pass: true`. Evidence is emitted to a
  caller-selected directory outside the source tree, and the VM is shut down with one current
  pre-Verifier checkpoint.
- A focused protocol-v4 campaign on the same networkless 24H2 VM loaded a renamed, signed transient
  driver after OAC was armed. OAC retained `post-start driver loads=1` and `load-gate trips=1`, made
  both immediate and post-cleanup scans fail, and reset only after a demand-start service restart.
  The test repeated under standard Driver Verifier with all 23 protocol checks passing, no recent
  bugcheck or minidump, and Verifier disabled afterward; the VM was rolled back to its sole clean
  checkpoint.
- An elevated user-mode smoke scan completed with a matching report sidecar and no temporary report
  remnants. It found the intentionally absent driver, two read-only monitoring handles, one real
  storage-source disagreement, and this host's explicitly disabled vulnerable-driver blocklist;
  the broad hook and overlay false positives discovered in the first smoke were corrected.

The checked-in driver remains intentionally unsigned; only the disposable-VM package is locally
test signed. The historical 24H2 campaign is evidence for that older source and exact build, not
for the current v5 foundation and not a universal Windows certification. Complete the current VM
gate and the documented Windows 10/11/Server, HVCI/VBS, hardware, and game-specific matrix, then use
an authorized production signing pipeline before deployment.

## Removed unsafe design

The current design removes the original custom page-fault ISR, CR3 replacement/thrashing, fixed
50-CPU NMI array, NMI-time stack unwinding/logging, fabricated `PsActiveProcessHead`, hardcoded
`EPROCESS`/`ETHREAD` layouts, page-table RAM mapping, self-unload IOCTL, `FILE_ANY_ACCESS` IOCTLs,
and pageable WFP classification. Those paths could corrupt affinity/IDT state, access freed or
version-dependent memory, recurse through a fault handler, or unload while returning through the
driver's own code.

## Primary references

- [Microsoft: `ObRegisterCallbacks`](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [Microsoft: kernel-mode code-signing requirements](https://learn.microsoft.com/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-)
- [Microsoft: vulnerable-driver block rules](https://learn.microsoft.com/windows/security/application-security/app-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [Upstream Turla Driver Loader reference](https://github.com/hfiref0x/TDL)
