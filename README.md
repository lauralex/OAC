# OAC
Open Anti-Cheat. A kernel-mode anticheat just for fun.

## Description
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


### IOCTLs
- **IOCTL_TEST_COMMUNICATION** (0x800): only for testing
- **IOCTL_TRIGGER_CR3_THRASH** (0x801): the main CR3 thrashing routine
- **IOCTL_UNLOAD_DRIVER** (0x802): the driver unloading routine


## Build
### Requirements
- Visual Studio (2022 preferably)
- Windows Software Development Kit ([SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/))
- Windows Driver Kit ([WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))
### External dependencies
- KDMapper (from here: https://github.com/TheCruZ/kdmapper)

## Run
1. Disable VDBL (Vulnerable Driver BlockList): [Instructions](https://www.elevenforum.com/t/enable-or-disable-microsoft-vulnerable-driver-blocklist-in-windows-11.10031/)
2. Open cmd, type: `kdmapper_Release.exe OAC.sys`
3. Open `OAC-Client.exe`
