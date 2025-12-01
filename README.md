# OAC
Open Anti-Cheat is a Windows kernel-mode playground that bundles multiple detection techniques into a single driver, plus a small user-mode client to trigger them. This document keeps the highlights concise and links directly into the code for easy navigation.

## Architecture at a Glance
- **Driver entry & IOCTL hub** — `OAC/main.c` creates the device, hooks IRP handlers, and routes user requests to feature modules:
  ```c
  switch (IrpStack->Parameters.DeviceIoControl.IoControlCode) {
  case IOCTL_TRIGGER_CR3_THRASH: TriggerCr3Thrash(); break;
  case IOCTL_TRIGGER_NMI_STACKWALK: TriggerNmiStackwalk(); break;
  case IOCTL_INITIALIZE_WFP_MONITOR: Status = InitializeWfpMonitor(DeviceObject); break;
  }
  ```
  [See the full dispatch table.](OAC/main.c)
- **Anti-virtualization CR3 thrash** — `OAC/cr3_thrasher.c` builds a minimalist page table, swaps in a custom PF handler, and intentionally faults after rewriting CR3 to stress hypervisors:
  ```c
  MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, &PageFaultIsr);
  G_OriginalCr3 = __readcr3();
  __writecr3(Cr3.AsUInt);
  *(volatile char*)0x0 = 1; // deliberate fault
  ```
  [Implementation details.](OAC/cr3_thrasher.c)
- **NMI-driven integrity sweeps** — `OAC/stackwalk.c` registers an NMI callback, locates the `KTRAP_FRAME`, unwinds the stack, and queues addresses for signature and CR3 validation:
  ```c
  PKTRAP_FRAME TrapFrame = FindNmiTrapFrame();
  RetrievedRipArray[0] = ContextRecord.Rip;
  PSIGNATURE_CHECK_ITEM CheckItem = &NmiContext->CheckItemPool[ItemIndex];
  ExInterlockedInsertTailList(&NmiContext->PendingCheckList, &CheckItem->ListEntry,
                              &NmiContext->CheckListLock);
  ```
  [Read the callback flow.](OAC/stackwalk.c)
- **Page table & CR3 validation** — `OAC/cr3_validation.c` cross-references captured CR3 values with active processes, while `OAC/pt_analyzer.c` walks user-mode page tables to flag kernel mappings.
- **Network shellcode monitor** — `OAC/wfp_monitor.c` registers ALE connect callouts and forwards each outbound flow to the shellcode analyzer for stack inspection and RWX checks.
- **User-mode client** — `OAC-Client/OAC-Client.cpp` exposes a simple menu that issues IOCTLs for each feature over the `\\.\OAC6` link.

## Feature Overview
- **Hypervisor crash test** (`IOCTL_TRIGGER_CR3_THRASH`): switch to custom page tables, force a page fault, and rely on the custom ISR to restore `CR3`/`IDTR` before resuming execution. [Code link.](OAC/cr3_thrasher.c)
- **NMI stack capture & signature verification** (`IOCTL_TRIGGER_NMI_STACKWALK`): fan out NMIs to all cores, unwind call stacks safely, and verify return addresses against signed kernel modules. [Code link.](OAC/stackwalk.c)
- **CR3 legitimacy & kernel mapping audit**: validate captured CR3s and scan user processes for U/S bit violations that map kernel space into user mode. [Code links.](OAC/cr3_validation.c) | [pt analyzer](OAC/pt_analyzer.c)
- **Outbound shellcode detection** (`IOCTL_INITIALIZE_WFP_MONITOR` / `IOCTL_DEINITIALIZE_WFP_MONITOR`): intercept connect attempts, unwind the originating thread, and flag RWX-backed return addresses with known shellcode signatures. [Code link.](OAC/wfp_monitor.c)

## Building
- Requires Visual Studio 2022, Windows SDK, and WDK.
- Build the solution: open `OAC.sln` and build the `Release` configuration for both driver and client.

## Running (test environments only)
1. Map the driver (e.g., with [KDMapper](https://github.com/TheCruZ/kdmapper)).
2. Run `OAC-Client.exe` as Administrator to send IOCTLs to the driver.
3. Disable protections such as Microsoft's vulnerable driver blocklist only on disposable VMs.

## IOCTL Cheat Sheet
| Control Code | Purpose |
| ------------ | ------- |
| `IOCTL_TEST_COMMUNICATION` | Sanity check between client and driver. |
| `IOCTL_TRIGGER_CR3_THRASH` | Run the anti-hypervisor thrash routine. |
| `IOCTL_TRIGGER_NMI_STACKWALK` | Capture stacks via NMIs and queue signature checks. |
| `IOCTL_INITIALIZE_WFP_MONITOR` | Register WFP callouts for outbound monitoring. |
| `IOCTL_DEINITIALIZE_WFP_MONITOR` | Tear down WFP filters and callouts. |
| `IOCTL_UNLOAD_DRIVER` | Cleanly unload the driver. |

## Credits
- [ia32-doc](https://github.com/ia32-doc/ia32-doc) for Intel architecture references.
- [Zydis](https://github.com/zyantific/zydis) for disassembly support.
