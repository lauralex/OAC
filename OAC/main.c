#include "internals.h"

// =================================================================================================
// == IOCTL Definitions
// =================================================================================================
#define IOCTL_TEST_COMMUNICATION    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CR3_THRASH    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// =================================================================================================
// == Page Table Pool Definitions
// =================================================================================================

// We'll allocate a pool of pages. 1 for PML4, and worst-case many others for each subsequent level
// for our distinct VAs. We'll allocate 50 pages for now, which is overkill but simple.
#define PAGE_TABLE_POOL_PAGES 50

// =================================================================================================
// == Function Prototypes
// =================================================================================================

// The function that performs the actual driver initialization.
NTSTATUS DriverInitialize(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
);

// Standard IRP and Unload handlers.
VOID DriverUnload(
    IN PDRIVER_OBJECT DriverObject
);
NTSTATUS IrpCreateCloseHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
);
NTSTATUS IrpDeviceIoCtlHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
);

VOID     TriggerCr3Thrash(void);
NTSTATUS MapVirtualAddressDynamically(PVOID pool_base, ULONG* next_free_page_index, PVOID target_va);

__declspec(noinline) PVOID GetRIP(void)
{
    return _ReturnAddress();
}

// =================================================================================================
// == Global Variables & External Functions
// =================================================================================================

const wchar_t* G_DRIVER_NAME  = L"\\Driver\\OAC6"; // For IoCreateDriver. Can be NULL for stealth.
const wchar_t* G_DEVICE_NAME  = L"\\Device\\OAC6";
const wchar_t* G_SYMLINK_NAME = L"\\DosDevices\\OAC6";

// Our assembly ISR. Tells the C compiler it exists elsewhere.
extern void PageFaultIsr(void); // Defined in isr.asm

extern void _sgdt(void*); // MSVC-provided intrinsic
extern void _str(void*);  // Defined in arch.asm
extern void _invd();      // Defined in arch.asm

// Global variable to share the original CR3 with our assembly ISR.
// This MUST be global.
UINT64 G_OriginalCr3 = 0;

// =================================================================================================
// == Driver Entry & Initialization
// =================================================================================================

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[+] kdmapper has called DriverEntry\n");

    // We can provide a driver name, or NULL for stealth
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, G_DRIVER_NAME);

    // Call the undocumented function IoCreateDriver.
    // This will create our DRIVER_OBJECT and call our DriverInitialize function.
    NTSTATUS status = IoCreateDriver(&driverName, &DriverInitialize);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateDriver failed: 0x%X\n", status);
        return status;
    }
    else
    {
        DbgPrint("[+] IoCreateDriver succeeded\n");
    }

    return status;
}

// This function is called by IoCreateDriver to perform driver initialization.
// All initialization code should be done here.
NTSTATUS NTAPI DriverInitialize(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS       status           = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject     = NULL;
    UNICODE_STRING deviceName       = {0};
    UNICODE_STRING symbolicLinkName = {0};

    RtlInitUnicodeString(&deviceName, G_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, G_SYMLINK_NAME);

    DbgPrint("[+] DriverInitialize called by IoCreateDriver\n");

    // Create the device object.
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Device object created successfully\n");

    // Create a symbolic link so user-mode applications can find the device.
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("[+] Symbolic link created successfully\n");

    // Set up the driver unload routine.
    DriverObject->DriverUnload = DriverUnload;
    // Set up the IRP handlers.
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

    // Clear the initialization flag to allow I/O.
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[+] Driver initialized successfully\n");
    return status;
}

//
// IRP Handlers and Unload Routine
//

// This will be called when the driver is to be unloaded (e.g., by another kernel component).
// It's good practice to have a cleanup routine.
VOID DriverUnload(
    IN PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symbolicLinkName = {0};
    RtlInitUnicodeString(&symbolicLinkName, G_SYMLINK_NAME);
    DbgPrint("[+] DriverUnload called\n");
    // Delete the symbolic link.
    IoDeleteSymbolicLink(&symbolicLinkName);
    DbgPrint("[+] Symbolic link deleted\n");

    // Delete the device object.
    if (DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
        DbgPrint("[+] Device object deleted\n");
    }

    // Delete the driver object itself.
    IoDeleteDriver(DriverObject);

    DbgPrint("[+] Driver unloaded successfully\n");
}

// Handler for when a user-mode application opens/closes a handle to the device.
NTSTATUS IrpCreateCloseHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[+] IrpCreateCloseHandler called\n");
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Handler for receiving IOCTLs from user-mode applications.
NTSTATUS IrpDeviceIoCtlHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack    = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status      = STATUS_SUCCESS;
    ULONG_PTR          information = 0;

    if (!irpStack)
    {
        status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_TEST_COMMUNICATION:
            DbgPrint("[+] IOCTL_TEST_COMMUNICATION received\n");
            // Just a test IOCTL to verify communication.
            break;
        case IOCTL_TRIGGER_CR3_THRASH:
            DbgPrint("[+] IOCTL_TRIGGER_CR3_THRASH received\n");
            TriggerCr3Thrash();
            break;
        case IOCTL_UNLOAD_DRIVER:
            DbgPrint("[+] IOCTL_UNLOAD_DRIVER received\n");

            // CRITICAL: We must complete the request back to user-mode BEFORE we
            // delete the device, otherwise the I/O manager will crash trying
            // to complete a request for a non-existent device.
            Irp->IoStatus.Status      = status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            // Now that the user-mode app has it answer, we can proceed with cleanup.
            DriverUnload(DeviceObject->DriverObject);

            // Note: The driver code is still in memory, but it is now disconnected.
            return status;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// =================================================================================================
// == CR3 Thrashing / Anti-Hypervisor Test Routine
// =================================================================================================

VOID TriggerCr3Thrash(void)
{
    PHYSICAL_ADDRESS new_pml4_pa     = {0};
    PVOID            page_table_pool = NULL;

    // Allocate our pool of pages for the new page table hierarchy.
    page_table_pool = MmAllocateContiguousMemory(PAGE_SIZE * PAGE_TABLE_POOL_PAGES, (PHYSICAL_ADDRESS){.QuadPart = -1});
    if (!page_table_pool)
    {
        DbgPrint("[-] MmAllocateContiguousMemory failed\n");
        return;
    }

    // Print page table pool address
    DbgPrint("[*] Page table pool VA: 0x%p\n", page_table_pool);

    RtlZeroMemory(page_table_pool, PAGE_SIZE * PAGE_TABLE_POOL_PAGES);
    new_pml4_pa = MmGetPhysicalAddress(page_table_pool);

    // Print physical address of the pool
    DbgPrint("[*] Page table pool PA: 0x%llX\n", new_pml4_pa.QuadPart);

    // The first page of the pool is the PML4. Subsequent pages are allocated as needed.
    ULONG next_free_page_idx = 1;

    // Get the IDT
    SEGMENT_DESCRIPTOR_REGISTER_64 idtr;
    __sidt(&idtr);

    // Step 1: Set up our minimal page tables
    DbgPrint("[+] Dynamically mapping all the required pages...\n");

    // Map all the required VAs. Our dynamic mapper will handle any index collisions.
#pragma warning(suppress: 4152) // Suppress "function/data pointer conversion" warning
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, &PageFaultIsr);
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, &G_OriginalCr3);
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, (PVOID)idtr.BaseAddress);

    PVOID currentRip = GetRIP();
    DbgPrint("[*] Current RIP: 0x%p\n", currentRip);
    MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, currentRip);

    // Handle IDT spanning a page boundary
    if (((ULONG_PTR)idtr.BaseAddress & ~0xFFF) != (((ULONG_PTR)idtr.BaseAddress + idtr.Limit) & ~0xFFF))
    {
        MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx,
                                     (PVOID)((PUCHAR)idtr.BaseAddress + idtr.Limit));
    }

    DbgPrint("[+] Pinning thread to current processor.\n");

    // Pin execution to the current processor.
    KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << KeGetCurrentProcessorNumberEx(NULL)));

    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64* pageFaultDescriptor = (SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64*)(idtr.BaseAddress
        + (14 * sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64)));


    // Print the address of the IDT entry
    DbgPrint("[*] IDT pageFaultDescriptor: 0x%p\n", pageFaultDescriptor);

    // Save the original CR3
    G_OriginalCr3 = __readcr3();
    DbgPrint("[*] Original CR3: 0x%llX\n", G_OriginalCr3);

    // Create a new IDT entry for our custom ISR
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 newPfDescriptor = {0};

    newPfDescriptor.OffsetLow                = (UINT16)((UINT64)PageFaultIsr & 0xFFFF);
    newPfDescriptor.SegmentSelector          = pageFaultDescriptor->SegmentSelector;          // Kernel code segment
    newPfDescriptor.Type                     = pageFaultDescriptor->Type;                     // 64-bit interrupt gate
    newPfDescriptor.DescriptorPrivilegeLevel = pageFaultDescriptor->DescriptorPrivilegeLevel; // Kernel level
    newPfDescriptor.Present                  = pageFaultDescriptor->Present;
    newPfDescriptor.OffsetMiddle             = (UINT16)(((UINT64)PageFaultIsr >> 16) & 0xFFFF);
    newPfDescriptor.OffsetHigh               = (UINT32)(((UINT64)PageFaultIsr >> 32) & 0xFFFFFFFF);
    newPfDescriptor.InterruptStackTable      = pageFaultDescriptor->InterruptStackTable; // Use same IST as original
    newPfDescriptor.Reserved                 = pageFaultDescriptor->Reserved;


    // Discover the existing IST stack used by the default PF handler
    UINT32 ist_index = pageFaultDescriptor->InterruptStackTable;
    if (ist_index == 0)
    {
        DbgPrint("[-] Original Page Fault handler does not use IST. Aborting.\n");
        KeRevertToUserAffinityThreadEx(oldAffinity);
        MmFreeContiguousMemory(page_table_pool);
        return;
    }

    DbgPrint("[*] Original Page Fault handler IST index: %u\n", ist_index);

    SEGMENT_DESCRIPTOR_REGISTER_64 gdtr         = {0};
    SEGMENT_SELECTOR               tss_selector = {0};
    _sgdt(&gdtr);
    _str(&tss_selector);
    SEGMENT_DESCRIPTOR_64* tss_descriptor = (SEGMENT_DESCRIPTOR_64*)(gdtr.BaseAddress + tss_selector.Index * sizeof(
        UINT64));

    UINT64 tss_base = ((UINT64)(tss_descriptor->BaseAddressLow)) |
        ((UINT64)(tss_descriptor->BaseAddressMiddle) << 16) |
        ((UINT64)(tss_descriptor->BaseAddressHigh) << 24) |
        ((UINT64)(tss_descriptor->BaseAddressUpper) << 32);

    TASK_STATE_SEGMENT_64* tss = (TASK_STATE_SEGMENT_64*)tss_base;

    // Get the stack top from the correct IST entry.
    // The TSS struct has Ist1..7, which corresponds to indices 1..7.
    UINT64 ist_stack_top  = *(&tss->Ist1 + (ist_index - 1));
    UINT64 ist_stack_base = ist_stack_top - 0x6000; // Assume 24KB stack size
    DbgPrint("[*] IST stack for PF handler: 0x%llX - 0x%llX\n", ist_stack_base, ist_stack_top);

    // Map all pages of the discovered IST stack
    for (UINT64 addr = ist_stack_base; addr < ist_stack_top; addr += PAGE_SIZE)
    {
        MapVirtualAddressDynamically(page_table_pool, &next_free_page_idx, (PVOID)addr);
    }

    DbgPrint("[!!} Entering CRITICAL section. Disabling interrupts.\n");
    DbgPrint("[!!] Swapping IDT entry and thrashing CR3...\n");

    // --- CRITICAL SECTION START ---
    _disable(); // Disable Interrupts

    // == BYPASS WRITE PROTECTION TO MODIFY IDT ==
    UINT64 originalCr0 = __readcr0();
    UINT64 newCr0      = originalCr0 & (~0x10000); // Clear WP bit (bit 16)
    __writecr0(newCr0);
    // ===========================================

    // Save the original Page Fault handler entry struct
    SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64 originalPfDescriptor = {0};
    RtlCopyMemory(&originalPfDescriptor, pageFaultDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // Overwrite the IDT entry for the Page Fault handler
    RtlCopyMemory(pageFaultDescriptor, &newPfDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // == RE-ENABLE WRITE PROTECTION IMMEDIATELY ==
    __writecr0(originalCr0);
    // ============================================

    // Thrash CR3 to trigger page faults
    CR3 cr3                    = {.AsUInt = G_OriginalCr3};
    cr3.AddressOfPageDirectory = (new_pml4_pa.QuadPart >> 12);

    __writecr3(cr3.AsUInt);

    // Cause an unconditional VM-exit on some hypervisors.
    _invd();

    // Deliberately cause a page fault. This MUST fail.
    // The write is volatile to prevent compiler optimization.
    *(volatile char*)0xDEADBEEF = 1;

    // --- EXECUTION RESUMES HERE AFTER ISR RESTORES ORIGINAL CR3 ---
    // The CPU state is now back to normal, but interrupts are still off.

    // == BYPASS WRITE PROTECTION TO MODIFY IDT ==
    originalCr0 = __readcr0();
    newCr0      = originalCr0 & (~0x10000); // Clear WP bit (bit 16)
    __writecr0(newCr0);
    // ===========================================

    // Restore the original IDT entry
    RtlCopyMemory(pageFaultDescriptor, &originalPfDescriptor, sizeof(SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64));

    // == RE-ENABLE WRITE PROTECTION IMMEDIATELY ==
    __writecr0(originalCr0);
    // ============================================

    // Restore original CR3 (should already be restored by the ISR, but just in case)
    __writecr3(G_OriginalCr3);

    _enable(); // Re-enable Interrupts
    // --- CRITICAL SECTION END ---

    DbgPrint("[!!] CRITICAL section finished. System stable.\n");

    // Restore the original thread affinity.
    KeRevertToUserAffinityThreadEx(oldAffinity);

    DbgPrint("[+] Thread affinity restored. Test complete.\n");

    // Step 2: Clean up the memory we allocated
    if (page_table_pool)
    {
        MmFreeContiguousMemory(page_table_pool);
        DbgPrint("[+] Freed page table memory.\n");
    }

    DbgPrint("[+] Test complete.\n");
}


/**
 * @brief Dynamically maps a virtual address into our custom page table hierarchy,
 *        allocating new tables from a pool as needed to resolve index collisions.
 *
 * @param pool_base The virtual address of our pre-allocated page pool.
 * @param next_free_page_index A pointer to an index tracking the next free page in the pool.
 * @param target_va The virtual address of the page we want to map.
 * @return STATUS_SUCCESS on success, or an error code.
 */
NTSTATUS MapVirtualAddressDynamically(PVOID pool_base, ULONG* next_free_page_index, PVOID target_va)
{
    PHYSICAL_ADDRESS pool_pa   = MmGetPhysicalAddress(pool_base);
    PHYSICAL_ADDRESS target_pa = MmGetPhysicalAddress(target_va);
    if (target_pa.QuadPart == 0)
    {
        DbgPrint("[-] Target VA 0x%p is not mapped in current page tables.\n", target_va);
        return STATUS_NOT_FOUND;
    }

    // The PML4 is always the first page in our pool.
    PML4E_64* pml4 = (PML4E_64*)pool_base;

    VIRTUAL_ADDRESS va = {.vaddr = (UINT64)target_va};

    // --- Level 1: PML4 -> PDPT ---
    PDPTE_64* pdpt;
    if (pml4[va.pml4_index].Present)
    {
        // Entry exists, follow it. Convert the PFN back to a VA within our pool.
        pdpt = (PDPTE_64*)((PUCHAR)pool_base + ((pml4[va.pml4_index].PageFrameNumber - (pool_pa.QuadPart >> 12)) <<
            12));
    }
    else
    {
        // No entry, allocate a new PDPT from our pool.
        if (*next_free_page_index >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pdpt = (PDPTE_64*)((PUCHAR)pool_base + (*next_free_page_index) * PAGE_SIZE);
        RtlZeroMemory(pdpt, PAGE_SIZE);

        PHYSICAL_ADDRESS pdpt_pa            = {.QuadPart = pool_pa.QuadPart + (*next_free_page_index) * PAGE_SIZE};
        pml4[va.pml4_index].Present         = 1;
        pml4[va.pml4_index].Write           = 1;
        pml4[va.pml4_index].PageFrameNumber = pdpt_pa.QuadPart >> 12;
        (*next_free_page_index)++;
    }

    // --- Level 2: PDPT -> PD ---
    PDE_64* pd;
    if (pdpt[va.pdpt_index].Present)
    {
        pd = (PDE_64*)((PUCHAR)pool_base + ((pdpt[va.pdpt_index].PageFrameNumber - (pool_pa.QuadPart >> 12)) << 12));
    }
    else
    {
        if (*next_free_page_index >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pd = (PDE_64*)((PUCHAR)pool_base + (*next_free_page_index) * PAGE_SIZE);
        RtlZeroMemory(pd, PAGE_SIZE);

        PHYSICAL_ADDRESS pd_pa              = {.QuadPart = pool_pa.QuadPart + (*next_free_page_index) * PAGE_SIZE};
        pdpt[va.pdpt_index].Present         = 1;
        pdpt[va.pdpt_index].Write           = 1;
        pdpt[va.pdpt_index].PageFrameNumber = pd_pa.QuadPart >> 12;
        (*next_free_page_index)++;
    }

    // --- Level 3: PD -> PT ---
    PTE_64* pt;
    if (pd[va.pd_index].Present)
    {
        pt = (PTE_64*)((PUCHAR)pool_base + ((pd[va.pd_index].PageFrameNumber - (pool_pa.QuadPart >> 12)) << 12));
    }
    else
    {
        if (*next_free_page_index >= PAGE_TABLE_POOL_PAGES)
        {
            DbgPrint("[-] Out of page table memory in pool.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pt = (PTE_64*)((PUCHAR)pool_base + (*next_free_page_index) * PAGE_SIZE);
        RtlZeroMemory(pt, PAGE_SIZE);
        PHYSICAL_ADDRESS pt_pa          = {.QuadPart = pool_pa.QuadPart + (*next_free_page_index) * PAGE_SIZE};
        pd[va.pd_index].Present         = 1;
        pd[va.pd_index].Write           = 1;
        pd[va.pd_index].PageFrameNumber = pt_pa.QuadPart >> 12;
        (*next_free_page_index)++;
    }

    // --- Level 4: PT -> Page ---
    pt[va.pt_index].Present         = 1;
    pt[va.pt_index].Write           = 1;
    pt[va.pt_index].PageFrameNumber = target_pa.QuadPart >> 12;

    return STATUS_SUCCESS;
}
