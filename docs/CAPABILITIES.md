# OAC capabilities

This document is the detailed capability reference for the current source. It separates the
production-control MVP from the elevated diagnostic scanner used only in isolated lab environments.
Implementation does not imply universal detection, prevention, or platform compatibility.

## Production-control boundary

| Capability | Current behavior |
|---|---|
| Standard-user entry point | `OAC-Launcher` connects only to the local restricted service and validates the server identity. It never receives a driver handle. |
| Privileged controller | `OACService` runs as a restricted service identity, owns the production driver session, and serializes status and launch operations. |
| Session authority | The driver binds authority to the service SID, creator process object, exact file object, random session identifier, and monotonic generation. |
| Early target binding | A bounded, one-use launch ticket matches the trusted creator and canonical executable path in the process-creation callback. |
| Suspended launch | The service resolves and holds the executable under the caller identity, creates it suspended with the caller's primary token, confirms the exact process handle, and then resumes the first thread. |
| Target-tree containment | The service assigns the confirmed target to an unnamed kill-on-close job before resume. Children inherit the job, and graceful stop or service failure terminates the tree. |
| Session-loss reporting | A device-lifetime monotonic sequence and stable loss reason let a replacement service distinguish requested shutdown from unexpected controller loss. |
| Retained alerts | High and critical typed records remain in a dedicated queue until the controlling service acknowledges an exact delivered sequence. Full-queue loss preserves existing data, records severity counts, and revokes production authority. |
| Operational events | Info, low, and medium records use an independent bounded queue with explicit sequence gaps and drop counts, so inventory pressure cannot overwrite retained alerts. |
| Paged snapshots | One frozen kernel-module inventory is bound to the current session, random snapshot identity, scan identity, cursor generation, and 30-second expiration. |
| Bounded target sampling | An independent service health loop queues incremental memory-region and thread-context slices into one coalescing worker slot. Fixed time, byte, region, and thread budgets plus cancellation and resume guards are reported through status metrics. |
| Handle protection | Signed object callbacks filter selected dangerous user-mode process and thread rights for the bound target. |
| Cleanup and retirement | Per-file cleanup revokes authority and completes rundown. A cleaned session that still references a live target remains as an unusable tombstone until target exit. |
| Protocol isolation | Production and diagnostic authority are mutually exclusive on each file object. |

The current production path intentionally supports one target and no command-line arguments.
Authenticated evidence upload, signed authorization, backend leases, and target-session reuse
remain planned work.

## Lab scanner matrix

The following broad diagnostic capabilities belong to `OAC-Client` and require explicit
`LabMode=1`. The production service does not expose this diagnostic interface; its smaller target
worker currently reports bounded coverage and performance metrics rather than policy findings.

| Capability | Implementation |
|---|---|
| Process and thread handle protection | `ObRegisterCallbacks` process/thread create and duplicate filtering strips terminate, injection, virtual-memory, context, duplication, and suspension rights. Existing handles are inventoried and reported. |
| Hidden processes | Toolhelp, PSAPI, and `NtQuerySystemInformation` cross-views are compared with kernel process and handle/object-owner snapshots. Live-process revalidation reduces churn false positives. |
| Hidden kernel modules | `AuxKlibQueryModuleInformation` and system-module cross-views are combined with load-image telemetry, IDT/LSTAR validation, and system-thread start addresses outside known modules. |
| Suspicious user modules | Three-view module inventory, explicit cheat/injector indicators, separately classified overlays/hooking modules, loader-backed IAT/export checks, and executable private-region inspection. |
| Driver inventory and policy | Kernel and PSAPI inventories use a shared conservative family policy, 542 compiled exact Authenticode SHA-256 denies, embedded-or-catalog trust validation, and individual records where paths resolve. |
| Post-start driver load latch | Every normal helper-driver load after OAC starts permanently records the event and can fail the configured gate even after rapid unload, file deletion, telemetry draining, or loader-trace cleanup. |
| Open handles | An extended system-handle snapshot is written to `oac-open-handles.csv`; target handles are correlated by kernel object identity. |
| Storage and devices | Logical volumes, DOS device names, physical-drive descriptors, and all present PnP devices are inventoried. |
| Privacy-preserving hardware identity | Bounded SMBIOS, storage, GPT/MBR, mount-manager, PnP/container, NIC, EDID, battery, HID/Bluetooth, and ACPI evidence is normalized and cross-checked. Placeholders and removable-only anchors are separated, and raw identifiers are not written to reports. |
| Debugger state | User-mode debugger APIs, native process debug classes, dynamically resolved kernel debug-port state, kernel debugger globals, and DR6/DR7 are checked. |
| Loader-independent kernel anomalies | System-thread start addresses and selected kernel control-flow targets outside loader modules are inspected. Exact-build profiles may add unloaded-driver and PiDDB observations. |
| Kernel integrity | Per-processor CR0/CR4/EFER, syscall MSRs, IDTR/GDTR, IDT-gate ownership, selected kernel exports, bounded IAT targets, OAC dispatch state, and OAC self-image integrity are checked. |
| Physical-memory handles | Kernel object identity is compared with `\Device\PhysicalMemory`. |
| Executable memory | Private or mapped executable regions, writable-executable pages, PE structure, mapped paths, direct syscall stubs, and bounded printable-string context are inspected. |
| Overlay windows | Visible topmost, layered, transparent, and no-activate windows intersecting the target are correlated with their owning processes. |
| Services | Win32 and driver services are inventoried in `oac-services.csv`; suspicious names and paths are elevated as evidence. |
| User stacks | Target threads are briefly suspended with guaranteed resume and walked with `StackWalk64`; executable frames outside modules are reported. |
| System threads | Kernel System-process thread starts are checked against loaded-driver ranges. |
| Virtualization and platform state | Repeated user/kernel CPUID checks, per-CPU consistency, firmware indicators, Secure Boot, VBS/HVCI, Code Integrity options, kernel-debugger state, and contradictions are reported separately. Timing is never a standalone verdict. |
| Instrumentation and debug hardening | Native instrumentation callbacks are queried. Opt-in lab switches can patch `DbgUiRemoteBreakin` and apply `ThreadHideFromDebugger` with explicit target mutation. |
| Processor sampling | A dynamically sized nonpaged response captures control/debug registers, syscall MSRs, descriptors, CPUID namespaces, and TSC_AUX per processor. The IPI routine copies metadata only; analysis occurs later at PASSIVE_LEVEL. |

## Evidence and policy semantics

OAC correlates independent observations and preserves confidence and policy state. The diagnostic
client can enforce a chosen finding threshold, but a finding remains evidence rather than an
automatic claim that a process is malicious.

Production evidence records preserve the kernel session, generation, sequence, timestamp, rule,
severity, confidence, category, and fixed provenance fields. The service currently keeps a bounded
in-memory alert handoff; authenticated persistence and server acknowledgement are later work.

Diagnostic reports use a per-run identifier, sequence and timestamps, an unkeyed SHA-256 finding
chain, artifact digests, atomic replacement, and a checksum sidecar. These detect accidental or
after-the-fact modification; they do not authenticate the scanner. Authenticated upload, server
challenges, nonce expiry, and evidence acknowledgement remain production work.

### Vulnerable-driver policy

`OAC-Client/driver_hash_policy.inc` is a compiled snapshot so the lab scanner does not depend on the
host's vulnerable-driver blocklist toggle or HVCI state. Regeneration is hash-pinned through
`tools/Update-OACDriverPolicy.ps1`; maintainers must review the upstream policy version, archive
digest, rule count, and generated diff before accepting an update.

Exact hashes are supplemented by conservative basename rules and the persistent post-start load
latch. A renamed helper cannot evade the latch, while loader-independent execution and control-flow
checks cover evidence that is not represented by a normal loaded-module entry.

The public image-load callback is observational and runs after mapping. OAC therefore does not claim
to veto every driver load or retroactively prevent code that already entered `DriverEntry`.

## Security boundaries

- `ObRegisterCallbacks` filters supported user-mode handles; it cannot defeat a hostile kernel
  driver, DMA device, compromised firmware, or hostile hypervisor.
- Optional private-kernel observations run only for an exact reviewed timestamp, image size, and
  checksum profile. Unknown builds use documented portable checks and report the unavailable
  capability instead of guessing offsets.
- Hardware, overlay, virtualization, and behavioral observations require deployment-specific
  allowlists and policy. They are not universally malicious conditions.
- Raw hardware identifiers are not report payloads, and removable peripherals are not promoted to
  stable core identity anchors.
- The driver remains demand-start and unsigned by default. The project does not provide a mapper or
  any workflow for disabling production host security controls.

## Deliberately excluded designs

The current design excludes the original custom page-fault ISR, CR3 replacement and thrashing,
fixed processor-count NMI buffers, NMI-time stack walking or logging, fabricated kernel list heads,
hard-coded `EPROCESS` or `ETHREAD` layouts, page-table RAM mapping, self-unload IOCTLs,
`FILE_ANY_ACCESS` control operations, and pageable WFP classification. Those approaches could
corrupt processor state, depend on private layouts, access freed memory, recurse through a fault
handler, or unload while returning through the driver's own code.

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Security model](SECURITY_MODEL.md)
- [Protocol reference](PROTOCOL.md)
- [Driver-load research](driver-load-review.md)
- [Hardware-identity research](hwid-review.md)
- [Microsoft `ObRegisterCallbacks`](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [Microsoft kernel-mode signing requirements](https://learn.microsoft.com/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-)
- [Microsoft vulnerable-driver block rules](https://learn.microsoft.com/windows/security/application-security/app-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
