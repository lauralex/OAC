# OAC

Open Anti-Cheat (OAC) is a kernel-mode proof-of-concept that stress-tests virtualization, monitors kernel integrity, and inspects outbound connections for shellcode indicators. The repository contains the driver (OAC/) and a small user-mode client (OAC-Client/) that triggers its IOCTLs.

## Architecture
- **Kernel driver** ([`OAC/main.c`](OAC/main.c)): creates the device, wires IOCTL handlers, and initializes the WFP monitor when requested by the client.
- **Detection modules**:
  - **CR3 thrash anti-hypervisor**: builds a minimal page-table set, swaps the IDT to a custom page-fault ISR, and temporarily overwrites `CR3` to provoke hypervisor failures (`TriggerCr3Thrash`).
    ```c
    // CR3 swap and deliberate page fault
    __writecr3(Cr3.AsUInt);
    *(volatile char*)0x0 = 1;
    __lidt(&Idtr);
    ```
    [Source](OAC/cr3_thrasher.c)
  - **NMI integrity sweep**: broadcasts NMIs, safely unwinds kernel stacks, queues return addresses for signature verification, validates captured `CR3` values against active processes, and scans process page tables for user-mode access into kernel ranges. Key routines live in [`OAC/stackwalk.c`](OAC/stackwalk.c), [`OAC/cr3_validation.c`](OAC/cr3_validation.c), and [`OAC/pt_analyzer.c`](OAC/pt_analyzer.c).
  - **WFP-driven shellcode detection**: registers ALE connect callouts, inspects the originating thread, and flags RWX stack frames that match shellcode signatures. See [`OAC/wfp_monitor.c`](OAC/wfp_monitor.c) and [`OAC/shellcode_analyzer.c`](OAC/shellcode_analyzer.c).
- **User-mode client** ([`OAC-Client/OAC-Client.cpp`](OAC-Client/OAC-Client.cpp)): opens the driver symbolic link and issues IOCTLs to trigger CR3 thrashing, NMI stack walks, and WFP monitoring.

## IOCTL Interface
| Control Code | Purpose |
| --- | --- |
| `0x800` | Connectivity test. |
| `0x801` | Trigger CR3 thrash routine. |
| `0x802` | Unload driver. |
| `0x803` | Trigger NMI integrity sweep. |
| `0x804` | Initialize WFP monitor. |
| `0x805` | De-initialize WFP monitor. |

## Building
- Visual Studio 2022 (or later)
- Windows SDK
- Windows Driver Kit (WDK)

## Usage
> **Warning:** This is kernel-mode code. Expect system instability and only run on isolated test machines/VMs.

1. Load the driver (e.g., with [KDMapper](https://github.com/TheCruZ/kdmapper)).
2. Run `OAC-Client.exe` as Administrator to send IOCTLs and watch kernel debugger output.
3. Use the menu to start/stop the WFP monitor, trigger NMI sweeps, or unload the driver.

## Credits
- [ia32-doc](https://github.com/ia32-doc/ia32-doc)
- [zydis](https://github.com/zyantific/zydis)
