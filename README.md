# OAC
Open Anti-Cheat. A kernel-mode anticheat just for fun.

## Description
### CR3 Thrashing Routine
For now, only a simple CR3 thrashing routine has been implemented.
It creates its own page tables to map these critical pages:
- A portion of the driver code
- The Page Fault handler
- A portion of the Interrupt Stack for the Page Fault handler
- The original IDT
- The original CR3 global variable

Everything else is **NOT** mapped; that's done purposefully to make incorrectly implemented hypervisors triple-fault.

The CR3 thrashing routine will then rewrite the **#PF** IDT entry to our own **#PF** handler (_WP bit in CR0 is temporarily disabled_), rewrite the CR3 DTB entry to our own PML4 (after saving the original CR3 value) and trigger a Page Fault deliberately.

After the **#PF** ISR is completed and the old CR3 value is restored, our driver code will continue its execution and restore the old **#PF** IDT entry.

### NMI Stackwalking Routine & Blocking Check
Here, we implemented a simple stackwalking routine that is triggered during a NMI.

The *NMI callback* is initialized by calling `KeRegisterNmiCallback`, an undocumented kernel function.

The *NMI* is triggered by calling `HalSendNMI`, another undocumented kernel function.

When the NMI is sent to all the logical processors (*except the sender one*), the NMI callback is invoked by the kernel after setting up additional context in the NMI's Interrupt Stack (i.e., **KTRAP_FRAME**).

We parse the **KTRAP_FRAME** structure from the NMI's Interrupt Stack and then we invoke some kernel functions that help us unwind each function.

After a small period of time, we check if there was an *NMI blocking* (i.e., some NMIs were not processed by the callback). If yes, this would indicate a problem or malicious activity in the kernel.

### Kernel Module Digital Signature Verification Routine
During the NMI stackwalking, we gather all the Program Counters for each level of the call stack for each logical core. After that, we initiate a digital signature check routine, which works in the following way:
1. Enqueue all the collected *Program Counters* (for the current logical core) to a synchronized linked list inside the **NMI Context** structure.
2. Start a DPC routine (Deferred Procedure Call) which will process all the elements in this synchronized linked list.
3. Check if each Program Counter in the list is in a *valid region* (i.e., a signed kernel module). An undocumented kernel function (`CiValidateFileObject`) is called for this purpose.
4. Print the verification state as a debug message: *CORRECT* or **INCORRECT** signature.

### IOCTLs
- **IOCTL_TEST_COMMUNICATION** (0x800): only for testing
- **IOCTL_TRIGGER_CR3_THRASH** (0x801): the main CR3 thrashing routine
- **IOCTL_UNLOAD_DRIVER** (0x802): the driver unloading routine
- **IOCTL_TRIGGER_NMI_STACKWALK** (0x803): the NMI stackwalking routine (including NMI blocking check and digital signature verification)


## Build [![Build Windows Kernel Driver](https://github.com/lauralex/OAC/actions/workflows/msbuild.yml/badge.svg)](https://github.com/lauralex/OAC/actions/workflows/msbuild.yml)
### Requirements
- Visual Studio (2022 preferably)
- Windows Software Development Kit ([SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/))
- Windows Driver Kit ([WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))
### External tools (optional, but suggested)
- KDMapper (from here: https://github.com/TheCruZ/kdmapper)

## Run
1. Disable VDBL (Vulnerable Driver BlockList): [Instructions](https://www.elevenforum.com/t/enable-or-disable-microsoft-vulnerable-driver-blocklist-in-windows-11.10031/)
2. Open cmd, type: `kdmapper_Release.exe OAC.sys`
3. Open `OAC-Client.exe`

## Credits
- ia32-doc (from here: https://github.com/ia32-doc/ia32-doc)
