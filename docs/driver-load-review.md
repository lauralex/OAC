# Windows driver-load review

## Scope and handling

This review was performed on read-only, hash-verified copies in a unique directory under the
current user's temporary folder. IDALib never opened the live files in `System32` in place.

| Image | File version | Size | SHA-256 |
|---|---:|---:|---|
| `ntoskrnl.exe` | 10.0.22621.7517 | 12,080,664 | `84F859B4987B24A30948D7139117146A9C658486E9271B7037CFFB1CE756C3A6` |
| `ci.dll` | 10.0.22621.5185 | 1,038,680 | `747ACF8BD77FBBEDAC645675A9FE637C9A2CACD29F524EC11D0C4A6F923347DF` |

The results below describe this exact pair of binaries. Private addresses and control-flow details
are research evidence, not a runtime compatibility contract.

## Normal demand-load path

PDB-backed analysis established this high-level path on the reviewed build:

1. `NtLoadDriver` delegates to `IopLoadDriverImage`.
2. The worker path reaches `IopLoadUnloadDriver` and `IopLoadDriver`.
3. `IopLoadDriver` resolves the service image and calls `MmLoadSystemImage` before it creates the
   driver object or calls `PnpCallDriverEntry`.
4. `MmLoadSystemImage` delegates to `MmLoadSystemImageEx`.
5. Executable-image section creation reaches `MiValidateSectionCreate`, which calls
   `SeValidateImageHeader`.
6. `SeValidateImageHeader` dispatches through the Code Integrity interface initialized from
   `ci.dll`. The reviewed `CiValidateImageHeader` path includes file-cache/policy evaluation and
   `CipValidateImageHash`; later page validation reaches `CiValidateImageData`.

This places the operating system's real allow/deny decision inside the image-section and Code
Integrity path, before `DriverEntry`. It also confirms why `PsSetLoadImageNotifyRoutine` is not a
veto mechanism: the documented callback returns `VOID` and observes an image that Windows has
already mapped.

## OAC design consequence

OAC does not patch Code Integrity callback pointers, hook `MmLoadSystemImage`, or modify private
kernel policy state. Those mechanisms are undocumented, build-specific, conflict with kernel
self-protection, and would make the anti-cheat itself indistinguishable from a kernel rootkit.

The demand-start design instead fails closed at the protected-session boundary:

- Before a game starts, OAC claims the control driver and performs a complete single-snapshot
  kernel/system preflight. This catches already-loaded denied drivers and probable manually mapped
  code without requiring a before-state snapshot.
- Launcher mode creates the game suspended, binds the referenced process object, repeats the
  target gate, and resumes only after the gate passes.
- While the game runs, the kernel callback records every normal driver image load. The client
  increments a monotonic post-start counter and, after configuration, a monotonic gate-trip
  counter before it emits bounded telemetry. Neither counter is drained with the event ring, and
  unloading the image or cleaning PiDDB/hash/unloaded-driver traces cannot reset them. The client
  polls the latch every 250 ms by default, evaluates current drivers against OAC's compiled family
  and exact-hash policy, and periodically repeats loader-independent kernel checks.
- A production finding revokes the game session. This prevents play on a compromised machine; it
  does not falsely claim that a third-party demand-start filter can veto Windows' own driver-load
  operation through a documented callback.

The latch begins at callback registration, before any client baseline. If a transient helper loads
after OAC starts but before the first scan, the nonzero counter makes that first scan fail closed.
The state resets only when the demand-start OAC driver is stopped and started again after restoring
a known-clean driver set. This intentionally trades compatibility with legitimate mid-session
driver installation for a strict protected-play boundary.

The supported operating-system mechanisms for a literal pre-map load veto remain Code Integrity
policy mechanisms. OAC can operate without HVCI or the host's Microsoft vulnerable-driver
blocklist, but it cannot safely replace the Windows Code Integrity decision point by patching it.

## Public references

- [Microsoft: load-image notification callback](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine)
- [Microsoft: `PsSetLoadImageNotifyRoutineEx`](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex)
- [Microsoft: recommended vulnerable-driver rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
