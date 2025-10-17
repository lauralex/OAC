# OAC
Open Anti-Cheat. A kernel-mode anticheat just for fun.

## Features

OAC implements several advanced detection vectors, each designed to uncover a different class of malicious activity.

### 1. Anti-Hypervisor CR3 Thrashing

This routine is designed to detect and crash poorly implemented hypervisors or virtualization-based cheats by manipulating memory management in a way that is valid on bare metal but often unhandled in a virtualized environment.

The detection works through the following sequence:
1.  **Minimalist Page Table Creation:** The driver constructs its own set of page tables in memory. These tables only map the absolute minimum required for the routine to function: a small portion of the driver's code, the custom Page Fault ISR, the Interrupt Stack, the IDT, and a variable to store the original `CR3`.
2.  **Context Swap:** In a critical, interrupt-disabled section, the driver saves the original `CR3` and swaps the Interrupt Descriptor Table Register (`IDTR`) to point to its own custom IDT.
3.  **CR3 Thrash:** The driver then overwrites the live `CR3` register with the physical address of its own minimalist PML4 table.
4.  **Deliberate Page Fault:** A page fault is intentionally triggered by accessing an unmapped address. A legitimate system will vector this fault through our custom ISR. Many simple hypervisors, however, will fail to properly handle the nested page fault during the `CR3` write VM-exit, leading to a system crash (triple fault).
5.  **Recovery:** Our custom Page Fault ISR immediately restores the original `CR3` value and resumes execution. The driver then restores the original `IDTR`, cleans up, and returns the system to a stable state.

### 2. NMI-Based System Integrity Scans

To perform analysis from a high-privilege, "out-of-band" context that is difficult for malware to intercept, OAC uses Non-Maskable Interrupts (NMIs). An NMI is sent to every logical processor, triggering a series of deferred checks that run at a lower, safer IRQL.

#### a. Kernel Stack Unwinding & NMI Blocking Check
When the NMI callback is invoked, it first locates the `KTRAP_FRAME` to get the state of the interrupted code. It then performs a safe stack walk to gather the instruction pointers (`RIP`) from the call stack of the code that was executing on each core. The safe unwinding is ensured by temporarily installing a custom Page Fault handler to gracefully handle potential memory access violations during the process. A failure to process all sent NMIs within a timeout period indicates that an NMI might have been blocked or dropped, a highly suspicious event.

#### b. Kernel Module Digital Signature Verification
The instruction pointers gathered during the NMI stack walk are enqueued for deferred analysis. A worker thread processes each `RIP` to verify that it resides within a legitimately signed kernel module. This is accomplished by using the undocumented `CiValidateFileObject` function, effectively checking the digital signature of the driver file on disk that corresponds to the code running in memory. An invalid signature is a strong indicator of an unsigned or maliciously patched driver.

#### c. CR3 Validation
The `CR3` register, which holds the physical address of the current process's page tables, is captured during the NMI. In the deferred worker thread, this captured `CR3` is validated against a list of `CR3` values from all active processes on the system (derived from `PsActiveProcessHead`). A `CR3` value that does not belong to any known process is a hallmark of a stealthy rootkit or hypervisor attempting to hide its own execution by using its own private memory space.

#### d. Suspicious Page Table Mapping Detection
This is a robust memory forensics routine that scans for fundamental security boundary violations within a process's memory layout.
-   **Threat Model:** Detects if a user-mode process has page table entries (PTEs) that grant it direct access (Read, Write, or Execute) to canonical kernel-space virtual addresses (`0xFFFF800000000000` and higher). Such a mapping is a critical security flaw and a common technique used in privilege escalation exploits.
-   **Methodology:** The routine performs a full, recursive walk of the page table hierarchy (PML4 -> PDPT -> PD -> PT) for each active user-mode process.
-   **Validation Logic:** For a virtual address to be accessible from user mode, the `User/Supervisor` bit must be set to `User` at **every single level** of the translation chain. This routine validates this condition and flags any kernel address that is accessible to user mode, also reporting on large page (2MB) mappings.

### 3. WFP-Based Shellcode Detection
This feature leverages the Windows Filtering Platform (WFP) to monitor outbound network connections and perform deep, heuristic-based analysis on the originating thread to detect in-memory shellcode, such as reverse shells.

-   **Threat Model:** Detects cheats or malware that inject raw shellcode into a process and then execute it to establish a network connection. A common pattern for this is creating a memory region with Read-Write-Execute (RWX) permissions.
-   **Methodology:** The detection process is triggered for every new outbound connection:
    1.  **WFP Callout:** The driver registers a callout at the `ALE_AUTH_CONNECT` layer, intercepting TCP/IP connection attempts before they are established.
    2.  **Thread Context Acquisition:** Upon interception, the driver identifies the originating process and thread. It then locates the thread's kernel trap frame (`KTRAP_FRAME`) to access the user-mode register state (like `RIP` and `RSP`) at the exact moment of the system call that initiated the connection.
    3.  **Heuristic Stack Unwinding:** A custom stack walker, built using the Zydis disassembler, unwinds the user-mode call stack of the originating thread. To ensure accuracy and avoid bad data, the stack walker validates each potential return address using several heuristics:
        *   The address must be a valid user-mode address.
        *   The memory page containing the address must have execute permissions.
        *   The address must be the target of a preceding `CALL` instruction, confirming a legitimate function call.
    4.  **RWX and Signature Scanning:** For each validated instruction pointer on the call stack, the driver performs two final checks:
        *   It queries the memory protection of the page. If the page is marked as `PAGE_EXECUTE_READWRITE` (RWX), it is flagged as highly suspicious, as legitimate code rarely resides in writable and executable memory.
        *   It scans the memory at the address for known shellcode byte patterns.
    5.  **Blocking Action:** If a return address points to an RWX memory region and contains a shellcode signature, the driver concludes that the connection is malicious. It then instructs WFP to block the connection, preventing the shellcode from communicating.

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
