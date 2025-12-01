# OAC
Open Anti-Cheat (OAC) is an educational Windows kernel-mode driver that exposes several anti-cheat detection routines and a thin user-mode client.

## Architecture at a glance
- **Driver entry & IOCTL dispatcher** — `DriverEntry` and `DriverInitialize` wire up the device, symbolic link, and IRP handlers in [`OAC/main.c`](OAC/main.c). The IOCTL switch fans out to each feature and cleanly tears down on `IOCTL_UNLOAD_DRIVER`.
- **CR3 manipulation pipeline** — low-level paging utilities live in [`OAC/mm.c`](OAC/mm.c) with the crash-oriented thrashing routine in [`OAC/cr3_thrasher.c`](OAC/cr3_thrasher.c) and validation helpers in [`OAC/cr3_validation.c`](OAC/cr3_validation.c).
- **NMI stack walker** — Non-Maskable Interrupt setup, safe unwinding, and deferred analysis are grouped in [`OAC/stackwalk.c`](OAC/stackwalk.c) and helpers like [`OAC/zyan_stackwalker.c`](OAC/zyan_stackwalker.c).
- **WFP network monitor** — callout registration and connection inspection live in [`OAC/wfp_monitor.c`](OAC/wfp_monitor.c) with shellcode heuristics in [`OAC/shellcode_analyzer.c`](OAC/shellcode_analyzer.c).
- **Support code** — signature checks via [`OAC/ci.c`](OAC/ci.c), module and serial logging utilities in [`OAC/module.c`](OAC/module.c) and [`OAC/serial_logger.c`](OAC/serial_logger.c), and interrupt stubs in [`OAC/isr.asm`](OAC/isr.asm).

## Features (with code pointers)
- **Anti-hypervisor CR3 thrash** — builds minimalist page tables, swaps CR3/IDT, triggers a deliberate fault, and restores state to expose fragile hypervisors. See `TriggerCr3Thrash` in [`OAC/cr3_thrasher.c`](OAC/cr3_thrasher.c) and the IOCTL hook in [`OAC/main.c`](OAC/main.c#L236-L249).
- **NMI-based integrity sweeps** — broadcasts NMIs, safely unwinds stacks, verifies module signatures (`CiValidateFileObject`), and checks captured CR3 values against active processes. Entry point `TriggerNmiStackwalk` in [`OAC/stackwalk.c`](OAC/stackwalk.c) and deferred analysis helpers in [`OAC/ci.c`](OAC/ci.c) / [`OAC/cr3_validation.c`](OAC/cr3_validation.c).
- **Suspicious page-table mapping scan** — recursively walks user process PTEs to detect kernel mappings reachable from user mode. Implemented in [`OAC/pt_analyzer.c`](OAC/pt_analyzer.c).
- **WFP shellcode detection** — intercepts outbound connects, reconstructs user-mode call stacks with Zydis, flags RWX frames, and blocks matching shellcode signatures. Callout setup in [`OAC/wfp_monitor.c`](OAC/wfp_monitor.c) with stack validation in [`OAC/shellcode_analyzer.c`](OAC/shellcode_analyzer.c).

## IOCTL surface
```c
// OAC/main.c
#define IOCTL_TEST_COMMUNICATION       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CR3_THRASH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_NMI_STACKWALK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INITIALIZE_WFP_MONITOR   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEINITIALIZE_WFP_MONITOR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Use `IrpDeviceIoCtlHandler` in [`OAC/main.c`](OAC/main.c#L230-L304) to map each control code to the routines above.

## Build
- Requires Visual Studio 2022, Windows SDK, and WDK. The solution file is [`OAC.sln`](OAC.sln) and the driver project lives in [`OAC/OAC.vcxproj`](OAC/OAC.vcxproj).
- GitHub Actions build uses [`msbuild.yml`](https://github.com/lauralex/OAC/actions/workflows/msbuild.yml).

## Usage
> **⚠️ Kernel-mode warning:** Running the driver can destabilize or crash the system. Only run on isolated test or virtual machines.

1. (Optional) Disable the Vulnerable Driver Blocklist if using `kdmapper` to load the driver.
2. Map `OAC.sys` with your loader (e.g., `kdmapper_Release.exe OAC.sys`).
3. Run the user client `OAC-Client.exe` to issue IOCTLs for CR3 thrash, NMI stackwalk, or WFP monitoring.

## Credits
- [ia32-doc](https://github.com/ia32-doc/ia32-doc) — Intel architecture documentation and structures.
- [Zydis](https://github.com/zyantific/zydis) — disassembler used for stack reconstruction.
