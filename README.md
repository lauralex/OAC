# OAC
Kernel-mode anti-cheat playground that stress-tests hypervisors, walks kernel stacks via NMIs, and inspects outbound connections for injected shellcode.

## Architecture at a glance
- **Driver entry & IOCTLs:** `DriverEntry` calls `DriverInitialize` to create the device, symbolic link, and IRP handlers, while the IOCTL switch routes user requests to each subsystem (`IOCTL_TRIGGER_CR3_THRASH`, `IOCTL_TRIGGER_NMI_STACKWALK`, `IOCTL_INITIALIZE_WFP_MONITOR`). [Source](OAC/main.c). ```c
NTSTATUS IrpDeviceIoCtlHandler(...) {
    switch (IoControlCode) {
    case IOCTL_TRIGGER_CR3_THRASH: TriggerCr3Thrash(); break;
    case IOCTL_TRIGGER_NMI_STACKWALK: TriggerNmiStackwalk(); break;
    case IOCTL_INITIALIZE_WFP_MONITOR: Status = InitializeWfpMonitor(DeviceObject); break;
    }
}
```
- **Memory forensics:** `TriggerCr3Thrash` builds minimal page tables, swaps the IDT to a custom page-fault ISR, thrashes `CR3`, and restores state to catch brittle hypervisors. [Source](OAC/cr3_thrasher.c). ```c
MapVirtualAddressDynamically(PageTablePool, &NextFreePageIdx, &PageFaultIsr);
G_OriginalCr3 = __readcr3();
__writecr3(Cr3.AsUInt);
*(volatile char*)0x0 = 1; // force PF under new CR3
```
- **NMI integrity sweeps:** `TriggerNmiStackwalk` seeds an NMI handler, broadcasts NMIs to other cores, and unwinds trap frames to verify module signatures and CR3 ownership in deferred work. [Source](OAC/stackwalk.c).
- **Network shellcode monitor:** `InitializeWfpMonitor` installs WFP callouts/filters so `WfpConnectCallout` can unwind user stacks for RWX frames and shellcode patterns before allowing outbound connects. [Source](OAC/wfp_monitor.c).

## Features
- **Anti-hypervisor CR3 thrash:** Minimal page tables plus a custom PF ISR provoke nested faults that expose weak virtualization. Invoke via `IOCTL_TRIGGER_CR3_THRASH`.
- **NMI-based integrity scans:** Broadcast NMIs, gather per-core trap frames, validate CR3s against active processes, and queue RIPs for signature checks. Triggered with `IOCTL_TRIGGER_NMI_STACKWALK`.
- **WFP shellcode detection:** Callouts at `ALE_AUTH_CONNECT` unwind user stacks with Zydis heuristics and block connections when RWX return addresses match shellcode signatures. Enabled with `IOCTL_INITIALIZE_WFP_MONITOR` and torn down with `IOCTL_DEINITIALIZE_WFP_MONITOR`.

## IOCTL interface
| Control code | Purpose |
| --- | --- |
| `IOCTL_TEST_COMMUNICATION` | Driver/client heartbeat. |
| `IOCTL_TRIGGER_CR3_THRASH` | Run the CR3 thrashing anti-hypervisor test. |
| `IOCTL_UNLOAD_DRIVER` | Unload the driver. |
| `IOCTL_TRIGGER_NMI_STACKWALK` | Launch NMI integrity sweep. |
| `IOCTL_INITIALIZE_WFP_MONITOR` | Register WFP callouts and filters. |
| `IOCTL_DEINITIALIZE_WFP_MONITOR` | Remove WFP hooks and clean up. |

## Build
- Visual Studio 2022
- Windows SDK
- Windows Driver Kit (WDK)

## Usage
> **Warning:** Kernel-mode code can BSOD and requires disabling protections. Use only on disposable test machines/VMs.

1. Disable the Vulnerable Driver BlockList (for `kdmapper`).
2. Map the driver: `kdmapper_Release.exe OAC.sys`.
3. Run `OAC-Client.exe` to send IOCTLs for each feature.

## Credits
- [ia32-doc](https://github.com/ia32-doc/ia32-doc)
- [zydis](https://github.com/zyantific/zydis)
