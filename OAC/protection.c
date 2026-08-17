#include "protection.h"
#include "session.h"
#include "telemetry.h"
#include "..\shared\oac_driver_policy.h"

#include <ntstrsafe.h>

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID 0x0004
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#endif

#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN 0x0080
#define THREAD_IMPERSONATE 0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif

static PVOID g_ObRegistrationHandle;
static EX_PUSH_LOCK g_IdentityLock;
static PVOID volatile g_ProtectedProcess;
static PVOID volatile g_ClientProcess;
static volatile LONG64 g_ProtectedPid;
static volatile LONG64 g_ClientPid;
static volatile LONG g_ConfigurationFlags;
static volatile LONG64 g_PostStartLoads;
static volatile LONG64 g_DriverGateTrips;
static BOOLEAN g_ProcessNotifyRegistered;
static BOOLEAN g_ThreadNotifyRegistered;
static BOOLEAN g_ImageNotifyRegistered;
typedef NTSTATUS (*OAC_PS_GET_PROCESS_EXIT_STATUS)(_In_ PEPROCESS Process);
typedef BOOLEAN (*OAC_PS_IS_PROTECTED_PROCESS)(_In_ PEPROCESS Process);
static OAC_PS_GET_PROCESS_EXIT_STATUS g_PsGetProcessExitStatus;
static OAC_PS_IS_PROTECTED_PROCESS g_PsIsProtectedProcess;
static OAC_PS_IS_PROTECTED_PROCESS g_PsIsProtectedProcessLight;

ACCESS_MASK OacRestrictedProcessRights(VOID)
{
    return PROCESS_TERMINATE |
           PROCESS_CREATE_THREAD |
           PROCESS_SET_SESSIONID |
           PROCESS_VM_OPERATION |
           PROCESS_VM_READ |
           PROCESS_VM_WRITE |
           PROCESS_DUP_HANDLE |
           PROCESS_CREATE_PROCESS |
           PROCESS_SET_QUOTA |
           PROCESS_SET_INFORMATION |
           PROCESS_SUSPEND_RESUME |
           PROCESS_SET_LIMITED_INFORMATION |
           DELETE |
           WRITE_DAC |
           WRITE_OWNER;
}

static ACCESS_MASK OacRestrictedThreadRights(VOID)
{
    return THREAD_TERMINATE |
           THREAD_SUSPEND_RESUME |
           THREAD_GET_CONTEXT |
           THREAD_SET_CONTEXT |
           THREAD_SET_INFORMATION |
           THREAD_SET_LIMITED_INFORMATION |
           THREAD_SET_THREAD_TOKEN |
           THREAD_IMPERSONATE |
           THREAD_DIRECT_IMPERSONATION |
           DELETE |
           WRITE_DAC |
           WRITE_OWNER;
}

static PEPROCESS OacReadProcessIdentity(_In_ PVOID volatile* Identity)
{
    return (PEPROCESS)InterlockedCompareExchangePointer(Identity, NULL, NULL);
}

static BOOLEAN OacIsTrustedRequestor(VOID)
{
    PEPROCESS current = PsGetCurrentProcess();
    return OacSessionIsControllerProcess(current) ||
           OacIsProtectedProcessObject(current);
}

static BOOLEAN OacIsProtectedWindowsRequestor(VOID)
{
    PEPROCESS current = PsGetCurrentProcess();
    return current == PsInitialSystemProcess ||
        (g_PsIsProtectedProcess != NULL && g_PsIsProtectedProcess(current)) ||
        (g_PsIsProtectedProcessLight != NULL &&
         g_PsIsProtectedProcessLight(current));
}

static BOOLEAN OacProcessIsActive(_In_ PEPROCESS Process)
{
    HANDLE processHandle = NULL;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    if (g_PsGetProcessExitStatus != NULL &&
        g_PsGetProcessExitStatus(Process) != STATUS_PENDING)
    {
        return FALSE;
    }

    timeout.QuadPart = 0;
    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        SYNCHRONIZE,
        *PsProcessType,
        KernelMode,
        &processHandle);
    if (!NT_SUCCESS(status)) return FALSE;
    status = ZwWaitForSingleObject(processHandle, FALSE, &timeout);
    ZwClose(processHandle);
    return status == STATUS_TIMEOUT;
}

static OB_PREOP_CALLBACK_STATUS OacPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Information)
{
    PEPROCESS targetProcess = NULL;
    HANDLE sourcePid;
    ACCESS_MASK* desiredAccess;
    ACCESS_MASK restricted;
    ACCESS_MASK before;
    ACCESS_MASK removed;
    BOOLEAN processOperation;
    BOOLEAN mutationAttempt;
    BOOLEAN protectedWindowsRequestor;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Information->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    if (Information->ObjectType == *PsProcessType)
    {
        targetProcess = (PEPROCESS)Information->Object;
        restricted = OacRestrictedProcessRights();
        processOperation = TRUE;
    }
    else if (Information->ObjectType == *PsThreadType)
    {
        targetProcess = IoThreadToProcess((PETHREAD)Information->Object);
        restricted = OacRestrictedThreadRights();
        processOperation = FALSE;
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    if (!OacIsProtectedProcessObject(targetProcess))
    {
        return OB_PREOP_SUCCESS;
    }

    sourcePid = PsGetCurrentProcessId();
    if (OacIsTrustedRequestor())
    {
        return OB_PREOP_SUCCESS;
    }
    /* Windows must finish creating the service-bound suspended process before
     * the service can confirm its handle. Keep protection active against
     * ordinary callers, but allow protected OS bootstrap processes during
     * this one bounded state. Full filtering applies before thread resume. */
    if (OacSessionTargetAwaitingConfirmation(targetProcess) &&
        OacIsProtectedWindowsRequestor())
    {
        return OB_PREOP_SUCCESS;
    }

    if (Information->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        desiredAccess = &Information->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else
    {
        desiredAccess = &Information->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    before = *desiredAccess;
    *desiredAccess &= ~restricted;
    if (before != *desiredAccess)
    {
        removed = before & ~*desiredAccess;
        mutationAttempt = processOperation
            ? (removed & ~PROCESS_VM_READ) != 0
            : TRUE;
        protectedWindowsRequestor = OacIsProtectedWindowsRequestor();
        OacReportFinding(
            protectedWindowsRequestor
                ? OacSeverityLow
                : (mutationAttempt ? OacSeverityMedium : OacSeverityLow),
            OacCategoryHandle,
            sourcePid,
            PsGetCurrentThreadId(),
            Information->Object,
            (ULONGLONG)before,
            protectedWindowsRequestor
                ? L"Stripped protected-object access from a protected Windows requestor: requested=0x%08X granted=0x%08X"
                : (mutationAttempt
                    ? L"Stripped protected-object mutation access: requested=0x%08X granted=0x%08X"
                    : L"Stripped protected-object read access: requested=0x%08X granted=0x%08X"),
            before,
            *desiredAccess);
    }

    return OB_PREOP_SUCCESS;
}

static VOID OacProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PEPROCESS releasedProtected = NULL;
    PEPROCESS releasedClient = NULL;
    OAC_SESSION_PROCESS_CREATE_RESULT createResult;

    if (CreateInfo != NULL)
    {
        if (!NT_SUCCESS(CreateInfo->CreationStatus)) return;
        createResult = OacSessionNotifyProcessCreate(
            Process,
            ProcessId,
            PsGetCurrentProcess(),
            CreateInfo->CreatingThreadId.UniqueProcess,
            CreateInfo->ImageFileName,
            (BOOLEAN)CreateInfo->FileOpenNameAvailable);
        if (createResult == OacSessionProcessCreateDenied)
        {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_IdentityLock);
    if (Process == OacReadProcessIdentity(&g_ProtectedProcess))
    {
        releasedProtected = (PEPROCESS)InterlockedExchangePointer(
            &g_ProtectedProcess,
            NULL);
        InterlockedExchange64(&g_ProtectedPid, 0);
        InterlockedAnd(
            &g_ConfigurationFlags,
            (LONG)~OAC_CONFIG_PROTECT_PROCESS);
    }
    if (Process == OacReadProcessIdentity(&g_ClientProcess))
    {
        releasedClient = (PEPROCESS)InterlockedExchangePointer(
            &g_ClientProcess,
            NULL);
        InterlockedExchange64(&g_ClientPid, 0);
        if (releasedProtected == NULL)
        {
            releasedProtected = (PEPROCESS)InterlockedExchangePointer(
                &g_ProtectedProcess,
                NULL);
        }
        InterlockedExchange64(&g_ProtectedPid, 0);
        InterlockedExchange(&g_ConfigurationFlags, 0);
    }
    ExReleasePushLockExclusive(&g_IdentityLock);
    KeLeaveCriticalRegion();

    OacSessionNotifyProcessExit(Process, ProcessId);

    if (releasedProtected != NULL)
    {
        OacReportFinding(
            OacSeverityInfo,
            OacCategoryProcess,
            ProcessId,
            NULL,
            NULL,
            0,
            L"Protected process exited");
        ObDereferenceObject(releasedProtected);
    }
    if (releasedClient != NULL)
    {
        OacReportFinding(
            OacSeverityInfo,
            OacCategoryProcess,
            ProcessId,
            NULL,
            NULL,
            0,
            L"Trusted OAC client exited; privileged IOCTLs now fail closed");
        ObDereferenceObject(releasedClient);
    }
}

static VOID OacThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    if (ProcessId == OacProtectedProcessId())
    {
        OacReportFinding(
            OacSeverityInfo,
            OacCategoryThread,
            ProcessId,
            ThreadId,
            NULL,
            Create ? 1 : 0,
            Create ? L"Protected-process thread created" : L"Protected-process thread exited");
    }
}

static BOOLEAN OacUnicodeEndsWith(
    _In_ PCUNICODE_STRING Value,
    _In_z_ PCWSTR Suffix)
{
    UNICODE_STRING suffix;
    if (Value == NULL || Value->Buffer == NULL)
    {
        return FALSE;
    }
    RtlInitUnicodeString(&suffix, Suffix);
    return RtlSuffixUnicodeString(&suffix, Value, TRUE);
}

static BOOLEAN OacUnicodeBaseNameEquals(
    _In_ PCUNICODE_STRING Value,
    _In_z_ PCWSTR Expected)
{
    UNICODE_STRING actual;
    UNICODE_STRING expected;
    USHORT characters;
    USHORT start;

    if (Value == NULL || Value->Buffer == NULL ||
        (Value->Length % sizeof(WCHAR)) != 0)
    {
        return FALSE;
    }

    characters = Value->Length / sizeof(WCHAR);
    start = characters;
    while (start != 0 && Value->Buffer[start - 1] != L'\\' &&
        Value->Buffer[start - 1] != L'/')
    {
        --start;
    }

    actual.Buffer = Value->Buffer + start;
    actual.Length = (USHORT)((characters - start) * sizeof(WCHAR));
    actual.MaximumLength = actual.Length;
    RtlInitUnicodeString(&expected, Expected);
    return RtlEqualUnicodeString(&actual, &expected, TRUE);
}

static BOOLEAN OacDeniedDriverImageName(_In_ PCUNICODE_STRING ImageName)
{
    static const PCWSTR names[] = { OAC_DRIVER_DENY_BASENAMES_W };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(names); ++i)
    {
        if (OacUnicodeBaseNameEquals(ImageName, names[i]))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN OacSuspiciousUserImageName(_In_ PCUNICODE_STRING ImageName)
{
    static const PCWSTR suffixes[] =
    {
        L"\\cheatengine-x86_64.dll", L"\\speedhack-i386.dll",
        L"\\dbk64.dll", L"\\injector.dll"
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(suffixes); ++i)
    {
        if (OacUnicodeEndsWith(ImageName, suffixes[i])) return TRUE;
    }
    return FALSE;
}

static VOID OacImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    WCHAR name[OAC_MAX_FINDING_TEXT];
    OAC_SEVERITY severity;
    ULONG configurationFlags;
    BOOLEAN deniedDriver = FALSE;
    BOOLEAN gateArmed = FALSE;

    if (FullImageName == NULL || FullImageName->Buffer == NULL)
    {
        (VOID)RtlStringCchCopyW(name, RTL_NUMBER_OF(name), L"<unnamed image>");
    }
    else
    {
        SIZE_T characters = min(
            (SIZE_T)(FullImageName->Length / sizeof(WCHAR)),
            RTL_NUMBER_OF(name) - 1);
        RtlCopyMemory(name, FullImageName->Buffer, characters * sizeof(WCHAR));
        name[characters] = L'\0';
    }

    configurationFlags = OacConfigurationFlags();
    severity = OacSeverityInfo;
    if (ProcessId == NULL)
    {
        (VOID)InterlockedIncrement64(&g_PostStartLoads);
        gateArmed = (configurationFlags &
            OAC_CONFIG_DRIVER_GATE) != 0;
        if (gateArmed)
        {
            (VOID)InterlockedIncrement64(&g_DriverGateTrips);
        }
        if (FullImageName != NULL && FullImageName->Buffer != NULL)
        {
            deniedDriver = OacDeniedDriverImageName(FullImageName);
        }
        severity = (gateArmed || deniedDriver)
            ? OacSeverityCritical
            : OacSeverityMedium;
    }
    else if (FullImageName != NULL && FullImageName->Buffer != NULL &&
        OacSuspiciousUserImageName(FullImageName))
    {
        severity = OacSeverityHigh;
    }

    if (ProcessId == NULL || severity >= OacSeverityHigh ||
        (((configurationFlags & OAC_CONFIG_ENABLE_IMAGE_LOG) != 0) &&
         ProcessId == OacProtectedProcessId()))
    {
        OacReportFinding(
            severity,
            ProcessId == NULL ? OacCategoryDriver : OacCategoryModule,
            ProcessId,
            NULL,
            ImageInfo != NULL ? ImageInfo->ImageBase : NULL,
            ImageInfo != NULL ? ImageInfo->ImageSize : 0,
            ProcessId == NULL && deniedDriver
                ? L"OAC deny-policy driver mapped after OAC started: %ls"
                : (ProcessId == NULL
                    ? (gateArmed
                        ? L"Driver-load gate tripped; Windows mapped a kernel image after the clean boundary: %ls"
                        : L"Kernel driver image loaded after OAC started and before session configuration: %ls")
                    : L"Image loaded: %ls"),
            name);
    }
}

NTSTATUS OacProtectionInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    OB_CALLBACK_REGISTRATION registration;
    OB_OPERATION_REGISTRATION operations[2];
    UNICODE_STRING altitude;
    UNICODE_STRING routineName;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);
    ExInitializePushLock(&g_IdentityLock);
    InterlockedExchange64(&g_PostStartLoads, 0);
    InterlockedExchange64(&g_DriverGateTrips, 0);
    RtlInitUnicodeString(&routineName, L"PsGetProcessExitStatus");
    g_PsGetProcessExitStatus = (OAC_PS_GET_PROCESS_EXIT_STATUS)
        MmGetSystemRoutineAddress(&routineName);
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
    g_PsIsProtectedProcess = (OAC_PS_IS_PROTECTED_PROCESS)
        MmGetSystemRoutineAddress(&routineName);
    RtlInitUnicodeString(&routineName, L"PsIsProtectedProcessLight");
    g_PsIsProtectedProcessLight = (OAC_PS_IS_PROTECTED_PROCESS)
        MmGetSystemRoutineAddress(&routineName);
    RtlZeroMemory(&registration, sizeof(registration));
    RtlZeroMemory(operations, sizeof(operations));

    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = OacPreOperation;
    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = OacPreOperation;

    RtlInitUnicodeString(&altitude, OAC_OB_ALTITUDE);
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.Altitude = altitude;
    registration.OperationRegistration = operations;

    status = ObRegisterCallbacks(&registration, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(OacProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        OacProtectionShutdown();
        return status;
    }
    g_ProcessNotifyRegistered = TRUE;

    status = PsSetCreateThreadNotifyRoutine(OacThreadNotify);
    if (!NT_SUCCESS(status))
    {
        OacProtectionShutdown();
        return status;
    }
    g_ThreadNotifyRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(OacImageNotify);
    if (!NT_SUCCESS(status))
    {
        OacProtectionShutdown();
        return status;
    }
    g_ImageNotifyRegistered = TRUE;
    return STATUS_SUCCESS;
}

VOID OacProtectionShutdown(VOID)
{
    PEPROCESS protectedProcess;
    PEPROCESS clientProcess;

    if (g_ImageNotifyRegistered)
    {
        (VOID)PsRemoveLoadImageNotifyRoutine(OacImageNotify);
        g_ImageNotifyRegistered = FALSE;
    }
    if (g_ThreadNotifyRegistered)
    {
        (VOID)PsRemoveCreateThreadNotifyRoutine(OacThreadNotify);
        g_ThreadNotifyRegistered = FALSE;
    }
    if (g_ProcessNotifyRegistered)
    {
        (VOID)PsSetCreateProcessNotifyRoutineEx(OacProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }
    if (g_ObRegistrationHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }

    protectedProcess = (PEPROCESS)InterlockedExchangePointer(
        &g_ProtectedProcess,
        NULL);
    clientProcess = (PEPROCESS)InterlockedExchangePointer(
        &g_ClientProcess,
        NULL);
    InterlockedExchange64(&g_ProtectedPid, 0);
    InterlockedExchange64(&g_ClientPid, 0);
    InterlockedExchange(&g_ConfigurationFlags, 0);
    InterlockedExchange64(&g_PostStartLoads, 0);
    InterlockedExchange64(&g_DriverGateTrips, 0);
    if (protectedProcess != NULL) ObDereferenceObject(protectedProcess);
    if (clientProcess != NULL) ObDereferenceObject(clientProcess);
    g_PsGetProcessExitStatus = NULL;
    g_PsIsProtectedProcess = NULL;
    g_PsIsProtectedProcessLight = NULL;
}

NTSTATUS OacConfigureProtection(
    _In_ const OAC_CONFIG_REQUEST* Request,
    _In_ HANDLE RequestorProcessId,
    _In_ const OAC_SESSION_LEASE* SessionLease)
{
    PEPROCESS clientProcess = NULL;
    PEPROCESS protectedProcess = NULL;
    PEPROCESS oldClient;
    PEPROCESS oldProtected;
    NTSTATUS status;
    const ULONG allowedFlags = OAC_CONFIG_PROTECT_PROCESS |
        OAC_CONFIG_ENABLE_IMAGE_LOG |
        OAC_CONFIG_DRIVER_GATE;

    if (Request->Version != OAC_PROTOCOL_VERSION ||
        Request->Size != sizeof(*Request) ||
        Request->ClientProcessId != HandleToULong(RequestorProcessId) ||
        Request->ClientProcessId == 0 ||
        Request->Reserved != 0 ||
        (Request->Flags & ~allowedFlags) != 0 ||
        (Request->Flags & OAC_CONFIG_DRIVER_GATE) == 0 ||
        (((Request->Flags & OAC_CONFIG_PROTECT_PROCESS) == 0) !=
         (Request->ProtectedProcessId == 0)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(
        ULongToHandle((ULONG)Request->ClientProcessId),
        &clientProcess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (clientProcess != PsGetCurrentProcess())
    {
        ObDereferenceObject(clientProcess);
        return STATUS_ACCESS_DENIED;
    }

    if ((Request->Flags & OAC_CONFIG_PROTECT_PROCESS) != 0)
    {
        if (Request->ProtectedProcessId == 0 ||
            Request->ProtectedProcessId > MAXULONG)
        {
            ObDereferenceObject(clientProcess);
            return STATUS_INVALID_PARAMETER;
        }

        status = PsLookupProcessByProcessId(
            ULongToHandle((ULONG)Request->ProtectedProcessId),
            &protectedProcess);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(clientProcess);
            return status;
        }
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_IdentityLock);
    if (!OacProcessIsActive(clientProcess) ||
        (protectedProcess != NULL && !OacProcessIsActive(protectedProcess)))
    {
        ExReleasePushLockExclusive(&g_IdentityLock);
        KeLeaveCriticalRegion();
        if (protectedProcess != NULL) ObDereferenceObject(protectedProcess);
        ObDereferenceObject(clientProcess);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    status = OacSessionBindTarget(
        SessionLease,
        protectedProcess,
        protectedProcess != NULL
            ? ULongToHandle((ULONG)Request->ProtectedProcessId)
            : NULL);
    if (!NT_SUCCESS(status))
    {
        ExReleasePushLockExclusive(&g_IdentityLock);
        KeLeaveCriticalRegion();
        if (protectedProcess != NULL) ObDereferenceObject(protectedProcess);
        ObDereferenceObject(clientProcess);
        return status;
    }

    oldProtected = (PEPROCESS)InterlockedExchangePointer(
        &g_ProtectedProcess,
        protectedProcess);
    oldClient = (PEPROCESS)InterlockedExchangePointer(
        &g_ClientProcess,
        clientProcess);
    InterlockedExchange64(&g_ClientPid, (LONG64)Request->ClientProcessId);
    InterlockedExchange64(&g_ProtectedPid, (LONG64)Request->ProtectedProcessId);
    InterlockedExchange(&g_ConfigurationFlags, (LONG)Request->Flags);
    ExReleasePushLockExclusive(&g_IdentityLock);
    KeLeaveCriticalRegion();
    if (oldProtected != NULL) ObDereferenceObject(oldProtected);
    if (oldClient != NULL) ObDereferenceObject(oldClient);

    OacReportFinding(
        OacSeverityInfo,
        OacCategoryGeneral,
        ULongToHandle((ULONG)Request->ProtectedProcessId),
        NULL,
        NULL,
        Request->Flags,
        L"Protection configured for PID %lu by trusted client PID %lu",
        (ULONG)Request->ProtectedProcessId,
        (ULONG)Request->ClientProcessId);
    return STATUS_SUCCESS;
}

HANDLE OacProtectedProcessId(VOID)
{
    HANDLE processId = OacSessionTargetProcessId();

    if (processId != NULL) return processId;
    return ULongToHandle(
        (ULONG)InterlockedCompareExchange64(&g_ProtectedPid, 0, 0));
}

HANDLE OacTrustedClientProcessId(VOID)
{
    return ULongToHandle((ULONG)InterlockedCompareExchange64(&g_ClientPid, 0, 0));
}

BOOLEAN OacIsProtectedProcessObject(_In_opt_ PVOID Object)
{
    return Object != NULL &&
        (Object == OacReadProcessIdentity(&g_ProtectedProcess) ||
         OacSessionIsTargetProcess((PEPROCESS)Object));
}

BOOLEAN OacIsTrustedClientProcess(_In_ PEPROCESS Process)
{
    return OacSessionIsControllerProcess(Process);
}

VOID OacProtectionRevokeController(_In_ PEPROCESS Controller)
{
    PEPROCESS releasedClient = NULL;
    PEPROCESS releasedProtected = NULL;

    if (Controller == NULL) return;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_IdentityLock);
    if (Controller == OacReadProcessIdentity(&g_ClientProcess))
    {
        releasedClient = (PEPROCESS)InterlockedExchangePointer(
            &g_ClientProcess,
            NULL);
        releasedProtected = (PEPROCESS)InterlockedExchangePointer(
            &g_ProtectedProcess,
            NULL);
        InterlockedExchange64(&g_ClientPid, 0);
        InterlockedExchange64(&g_ProtectedPid, 0);
        InterlockedExchange(&g_ConfigurationFlags, 0);
    }
    ExReleasePushLockExclusive(&g_IdentityLock);
    KeLeaveCriticalRegion();

    if (releasedProtected != NULL) ObDereferenceObject(releasedProtected);
    if (releasedClient != NULL) ObDereferenceObject(releasedClient);
}

ULONG OacConfigurationFlags(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_ConfigurationFlags, 0, 0);
}

ULONGLONG OacPostStartLoads(VOID)
{
    return (ULONGLONG)InterlockedCompareExchange64(
        &g_PostStartLoads,
        0,
        0);
}

ULONGLONG OacDriverGateTrips(VOID)
{
    return (ULONGLONG)InterlockedCompareExchange64(
        &g_DriverGateTrips,
        0,
        0);
}
