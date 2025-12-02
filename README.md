# OAC
Open Anti-Cheat. A kernel-mode anticheat just for fun. [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/lauralex/OAC)

## Features

OAC implements several advanced detection vectors.

### 1. Anti-Hypervisor CR3 Thrashing
Detects hypervisors by manipulating memory management (page tables and `CR3`) in ways that are valid on bare metal but often mishandled by virtualization.

*   **Implementation:** [`OAC/cr3_thrasher.c`](OAC/cr3_thrasher.c)
    *   **Minimalist Page Table Creation:** `TriggerCr3Thrash` creates a minimal page table hierarchy.
    *   **Context Swap:** Swaps IDT to a custom one using `__lidt`.
    *   **CR3 Thrash:** Overwrites `CR3` with a custom value (`__writecr3`) to trigger VM-exits.
    *   **Deliberate Page Fault:** Intentionally triggers a page fault to test exception handling.
*   **Recovery:** [`OAC/isr.asm`](OAC/isr.asm)
    *   **Page Fault ISR:** `PageFaultIsr` restores the original `CR3` and resumes execution.

### 2. NMI-Based System Integrity Scans
Uses Non-Maskable Interrupts (NMIs) to perform high-privilege, out-of-band analysis of system state.

*   **NMI Callback & Loop:** [`OAC/stackwalk.c`](OAC/stackwalk.c)
    *   `TriggerNmiStackwalk` broadcasts NMIs to all cores.
    *   `NmiCallback` handles the interrupt and initiates checks.
*   **Kernel Stack Unwinding:** [`OAC/stackwalk.c`](OAC/stackwalk.c)
    *   `PerformUnwindInSafeRegion` safely unwinds the stack to find executing code.
*   **Kernel Module Verification:** [`OAC/ci.c`](OAC/ci.c)
    *   `VerifyModuleSignatureByRip` verifies digital signatures of executing code.
*   **CR3 Validation:** [`OAC/cr3_validation.c`](OAC/cr3_validation.c)
    *   `IsCr3InProcessList` checks if the captured `CR3` belongs to a valid process.
*   **Suspicious Page Table Mapping:** [`OAC/pt_analyzer.c`](OAC/pt_analyzer.c)
    *   `AnalyzeProcessPageTables` detects user-mode mappings of kernel memory.

### 3. WFP-Based Shellcode Detection
Monitors outbound network connections and analyzes the originating thread for in-memory shellcode.

*   **WFP Callout:** [`OAC/wfp_monitor.c`](OAC/wfp_monitor.c)
    *   `WfpConnectCallout` intercepts connection attempts at `ALE_AUTH_CONNECT`.
*   **Thread Analysis:** [`OAC/shellcode_analyzer.c`](OAC/shellcode_analyzer.c)
    *   `AnalyzeThreadForShellcode` unwinds the stack of the connecting thread.
    *   `IsMemoryRwAndContainsSignature` checks for RWX permissions and shellcode signatures.
*   **Zydis Integration:** [`OAC/zyan_stackwalker.c`](OAC/zyan_stackwalker.c)
    *   Uses Zydis for heuristic stack unwinding.

## IOCTL Interface

The driver is controlled from a user-mode client via the following IOCTLs:

| Control Code                     | Hex Value | Description                                                                                             |
| -------------------------------- | --------- | ------------------------------------------------------------------------------------------------------- |
| `IOCTL_TEST_COMMUNICATION`       | `0x800`   | A simple test command to verify that the client and driver can communicate.                             |
| `IOCTL_TRIGGER_CR3_THRASH`       | `0x801`   | Executes the anti-hypervisor CR3 thrashing routine.                                                     |
| `IOCTL_UNLOAD_DRIVER`            | `0x802`   | Unloads the kernel driver.                                                                              |
| `IOCTL_TRIGGER_NMI_STACKWALK`    | `0x803`   | Triggers the NMI-based system integrity scans (stackwalk, signature check, CR3 validation, etc.).       |
| `IOCTL_INITIALIZE_WFP_MONITOR`   | `0x804`   | Registers the WFP callouts to begin monitoring outbound network connections.                            |
| `IOCTL_DEINITIALIZE_WFP_MONITOR` | `0x805`   | De-registers the WFP callouts and cleans up all related filters, stopping network monitoring.           |


## Build [![Build Windows Kernel Driver](https://github.com/lauralex/OAC/actions/workflows/msbuild.yml/badge.svg)](https://github.com/lauralex/OAC/actions/workflows/msbuild.yml)
### Requirements
- Visual Studio (2022 preferably)
- Windows Software Development Kit ([SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/))
- Windows Driver Kit ([WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))

## Usage

> **:warning: WARNING:** This is a kernel-mode driver. Running this code can lead to system instability or Blue Screen of Death (BSOD) errors. It requires disabling fundamental Windows security features. **Use this exclusively on a test machine or in a virtual machine.**

### External tools (optional, but suggested)
- **Kernel Driver Mapper:** A tool is required to map the driver into the kernel. [KDMapper](https://github.com/TheCruZ/kdmapper) is recommended.

### Running the Anti-Cheat
1. **Disable VDBL (Vulnerable Driver BlockList):** This security feature must be disabled as it may prevent `kdmapper`'s vulnerable driver from loading. [Instructions here](https://www.elevenforum.com/t/enable-or-disable-microsoft-vulnerable-driver-blocklist-in-windows-11.10031/).
2. **Map the driver:** Open an administrator command prompt and run `kdmapper_Release.exe OAC.sys`.
3. **Run the client:** Execute `OAC-Client.exe` to interact with the driver and trigger its features via the IOCTL interface.

## Credits
- [ia32-doc](https://github.com/ia32-doc/ia32-doc): for invaluable Intel architecture documentation and structures.
- [zydis](https://github.com/zyantific/zydis): for the powerful Zydis disassembler library.
