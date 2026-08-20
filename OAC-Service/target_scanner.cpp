#include "target_scanner.hpp"

#include <TlHelp32.h>
#include <strsafe.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>

#include "..\shared\oac_thread_suspension.hpp"
#include "..\shared\protocol\oac_validate.h"

namespace
{
using NtQueryInformationThreadFn = LONG(NTAPI*)(
    HANDLE,
    LONG,
    void*,
    ULONG,
    ULONG*);
using NtQueryInformationProcessFn = LONG(NTAPI*)(
    HANDLE,
    ULONG,
    void*,
    ULONG,
    ULONG*);

constexpr LONG kThreadQuerySetWin32StartAddress = 9;
constexpr ULONG kProcessInstrumentationCallback = 40;

struct InstrumentationCallbackInformation
{
    ULONG Version;
    ULONG Reserved;
    void* Callback;
};

std::uint64_t FileTimeValue(const FILETIME& value) noexcept
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) |
        value.dwLowDateTime;
}

std::uint64_t CurrentSystemTime100ns() noexcept
{
    FILETIME value{};
    GetSystemTimePreciseAsFileTime(&value);
    return FileTimeValue(value);
}

std::uint64_t CurrentUnbiasedTime100ns() noexcept
{
    ULONGLONG value = 0;
    if (QueryUnbiasedInterruptTime(&value)) return value;
    return GetTickCount64() * oac::kHundredNanosecondsPerMillisecond;
}

bool CurrentThreadCpuTime100ns(std::uint64_t& value) noexcept
{
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (!GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user))
        return false;
    const std::uint64_t kernelValue = FileTimeValue(kernel);
    const std::uint64_t userValue = FileTimeValue(user);
    if (kernelValue > (std::numeric_limits<std::uint64_t>::max)() - userValue)
        return false;
    value = kernelValue + userValue;
    return true;
}

void AddSaturating(std::uint64_t& destination, std::uint64_t value) noexcept
{
    constexpr std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    destination = value > maximum - destination
        ? maximum
        : destination + value;
}

bool IsExecutableProtection(DWORD protection) noexcept
{
    switch (protection & 0xFFu)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool CanReadProtection(DWORD protection) noexcept
{
    return (protection & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
}

} // namespace

namespace oac
{
TargetScanWorker::TargetScanWorker(HANDLE stopEvent) noexcept
    : stopEvent_(stopEvent),
      cancelEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      workEvent_(CreateEventW(nullptr, FALSE, FALSE, nullptr)),
      failureEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
    metrics_.State = OAC_IPC_SCAN_UNAVAILABLE;
}

TargetScanWorker::~TargetScanWorker()
{
    (void)Stop();
    if (failureEvent_ != nullptr) CloseHandle(failureEvent_);
    if (workEvent_ != nullptr) CloseHandle(workEvent_);
    if (cancelEvent_ != nullptr) CloseHandle(cancelEvent_);
}

bool TargetScanWorker::Ready() const noexcept
{
    return stopEvent_ != nullptr && cancelEvent_ != nullptr &&
        workEvent_ != nullptr && failureEvent_ != nullptr;
}

DWORD TargetScanWorker::Start(
    HANDLE targetProcess,
    DWORD targetProcessId,
    HANDLE targetUserToken) noexcept
{
    if (!Ready() || targetProcess == nullptr ||
        targetProcess == INVALID_HANDLE_VALUE || targetProcessId == 0 ||
        targetUserToken == nullptr || targetUserToken == INVALID_HANDLE_VALUE)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&started_, TRUE, FALSE) != FALSE)
        return ERROR_INVALID_STATE;

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    nextMemoryAddress_ = reinterpret_cast<std::uintptr_t>(
        systemInfo.lpMinimumApplicationAddress);
    maximumMemoryAddress_ = reinterpret_cast<std::uintptr_t>(
        systemInfo.lpMaximumApplicationAddress);
    pageSize_ = systemInfo.dwPageSize != 0 ? systemInfo.dwPageSize : 4096;
    if (nextMemoryAddress_ >= maximumMemoryAddress_)
    {
        InterlockedExchange(&started_, FALSE);
        return ERROR_INVALID_ADDRESS;
    }

    targetProcess_ = targetProcess;
    targetProcessId_ = targetProcessId;
    targetUserToken_ = targetUserToken;
    AcquireSRWLockExclusive(&observationLock_);
    for (auto& observation : observations_) observation = {};
    observationRead_ = 0;
    observationWrite_ = 0;
    observationCount_ = 0;
    ReleaseSRWLockExclusive(&observationLock_);
    for (auto& key : observedKeys_) key = {};
    observedKeyCount_ = 0;
    AcquireSRWLockExclusive(&metricsLock_);
    metrics_.State = OAC_IPC_SCAN_READY;
    ReleaseSRWLockExclusive(&metricsLock_);

    thread_ = CreateThread(nullptr, 0, ThreadEntry, this, 0, nullptr);
    if (thread_ == nullptr)
    {
        const DWORD error = GetLastError();
        PublishFailure(error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error);
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
    }
    return ERROR_SUCCESS;
}

DWORD TargetScanWorker::QueueSlice() noexcept
{
    if (InterlockedCompareExchange(&started_, FALSE, FALSE) == FALSE ||
        thread_ == nullptr)
    {
        return ERROR_INVALID_STATE;
    }
    if (CancellationRequested()) return ERROR_OPERATION_ABORTED;
    if (InterlockedCompareExchange(&pending_, TRUE, FALSE) != FALSE)
    {
        AcquireSRWLockExclusive(&metricsLock_);
        AddSaturating(metrics_.SlicesCoalesced, 1);
        ReleaseSRWLockExclusive(&metricsLock_);
        return ERROR_SUCCESS;
    }

    AcquireSRWLockExclusive(&metricsLock_);
    AddSaturating(metrics_.SlicesQueued, 1);
    ReleaseSRWLockExclusive(&metricsLock_);
    if (!SetEvent(workEvent_))
    {
        const DWORD error = GetLastError();
        InterlockedExchange(&pending_, FALSE);
        AcquireSRWLockExclusive(&metricsLock_);
        if (metrics_.SlicesQueued != 0) --metrics_.SlicesQueued;
        ReleaseSRWLockExclusive(&metricsLock_);
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
    }
    return ERROR_SUCCESS;
}

DWORD TargetScanWorker::Stop() noexcept
{
    if (cancelEvent_ != nullptr) (void)SetEvent(cancelEvent_);
    if (workEvent_ != nullptr) (void)SetEvent(workEvent_);
    if (thread_ == nullptr) return ERROR_SUCCESS;

    DWORD wait = WaitForSingleObject(thread_, 5000);
    DWORD result = ERROR_SUCCESS;
    if (wait == WAIT_TIMEOUT)
    {
        result = ERROR_TIMEOUT;
        (void)CancelSynchronousIo(thread_);
        wait = WaitForSingleObject(thread_, INFINITE);
    }
    if (wait != WAIT_OBJECT_0 && result == ERROR_SUCCESS)
    {
        result = GetLastError();
        if (result == ERROR_SUCCESS) result = ERROR_GEN_FAILURE;
    }
    CloseHandle(thread_);
    thread_ = nullptr;
    targetUserToken_ = nullptr;
    return result;
}

void TargetScanWorker::RecordHealthIteration(
    std::uint64_t delay100ns) noexcept
{
    AcquireSRWLockExclusive(&metricsLock_);
    AddSaturating(metrics_.HealthIterations, 1);
    metrics_.MaximumHealthDelay100ns = (std::max)(
        metrics_.MaximumHealthDelay100ns,
        delay100ns);
    ReleaseSRWLockExclusive(&metricsLock_);
}

void TargetScanWorker::CopyMetrics(
    OAC_IPC_SCAN_METRICS& metrics) const noexcept
{
    AcquireSRWLockShared(&metricsLock_);
    metrics = metrics_;
    ReleaseSRWLockShared(&metricsLock_);
}

bool TargetScanWorker::TakeObservation(
    TargetObservation& observation) noexcept
{
    AcquireSRWLockExclusive(&observationLock_);
    if (observationCount_ == 0)
    {
        ReleaseSRWLockExclusive(&observationLock_);
        return false;
    }
    observation = observations_[observationRead_];
    observations_[observationRead_] = {};
    observationRead_ = (observationRead_ + 1) % observations_.size();
    --observationCount_;
    ReleaseSRWLockExclusive(&observationLock_);
    return true;
}

HANDLE TargetScanWorker::FailureEvent() const noexcept
{
    return failureEvent_;
}

DWORD TargetScanWorker::FailureError() const noexcept
{
    return static_cast<DWORD>(InterlockedCompareExchange(
        const_cast<volatile LONG*>(&failureError_),
        ERROR_SUCCESS,
        ERROR_SUCCESS));
}

DWORD WINAPI TargetScanWorker::ThreadEntry(void* context) noexcept
{
    return static_cast<TargetScanWorker*>(context)->Run();
}

DWORD TargetScanWorker::Run() noexcept
{
    HANDLE waits[] = {stopEvent_, cancelEvent_, targetProcess_, workEvent_};
    for (;;)
    {
        const DWORD wait = WaitForMultipleObjects(4, waits, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_OBJECT_0 + 1 ||
            wait == WAIT_OBJECT_0 + 2)
        {
            const bool pendingCancelled =
                InterlockedExchange(&pending_, FALSE) != FALSE;
            PublishStopped(pendingCancelled);
            return ERROR_SUCCESS;
        }
        if (wait != WAIT_OBJECT_0 + 3)
        {
            DWORD error = GetLastError();
            if (error == ERROR_SUCCESS) error = ERROR_GEN_FAILURE;
            PublishFailure(error);
            return error;
        }
        if (InterlockedExchange(&pending_, FALSE) == FALSE) continue;

        AcquireSRWLockExclusive(&metricsLock_);
        metrics_.State = OAC_IPC_SCAN_RUNNING;
        ReleaseSRWLockExclusive(&metricsLock_);

        SliceReport report{};
        report.error = RunSlice(report);
        PublishReport(report);
        if (report.error == ERROR_OPERATION_ABORTED)
        {
            PublishStopped(false);
            return ERROR_SUCCESS;
        }
        if (report.error != ERROR_SUCCESS)
        {
            PublishFailure(report.error);
            return report.error;
        }

        AcquireSRWLockExclusive(&metricsLock_);
        metrics_.State = OAC_IPC_SCAN_READY;
        ReleaseSRWLockExclusive(&metricsLock_);
    }
}

DWORD TargetScanWorker::RunSlice(SliceReport& report) noexcept
{
    report.startTime100ns = CurrentSystemTime100ns();
    const std::uint64_t started100ns = CurrentUnbiasedTime100ns();
    std::uint64_t startedCpu100ns = 0;
    const bool cpuStartValid = CurrentThreadCpuTime100ns(startedCpu100ns);
    const std::uint64_t budgetDuration =
        static_cast<std::uint64_t>(kScanSliceBudgetMilliseconds) *
        kHundredNanosecondsPerMillisecond;
    ScanSliceBudget budget{};
    budget.deadline100ns = started100ns >
            (std::numeric_limits<std::uint64_t>::max)() - budgetDuration
        ? (std::numeric_limits<std::uint64_t>::max)()
        : started100ns + budgetDuration;
    ScanSliceProgress progress{};

    DWORD error = CancellationRequested()
        ? ERROR_OPERATION_ABORTED
        : InspectInstrumentationCallback(report);
    if (error == ERROR_SUCCESS)
        error = InspectNextThread(budget, progress, report);
    if (error == ERROR_SUCCESS)
        error = InspectMemory(budget, progress, report);
    if (error == ERROR_SUCCESS && CancellationRequested())
        error = ERROR_OPERATION_ABORTED;

    if (error == ERROR_SUCCESS && memorySweepComplete_ && threadSweepComplete_)
    {
        report.sweepCompleted = true;
        SYSTEM_INFO systemInfo{};
        GetNativeSystemInfo(&systemInfo);
        nextMemoryAddress_ = reinterpret_cast<std::uintptr_t>(
            systemInfo.lpMinimumApplicationAddress);
        lastThreadId_ = 0;
        memorySweepComplete_ = false;
        threadSweepComplete_ = false;
    }

    const std::uint64_t ended100ns = CurrentUnbiasedTime100ns();
    report.duration100ns = ended100ns >= started100ns
        ? ended100ns - started100ns
        : 0;
    report.endTime100ns = (std::max)(
        report.startTime100ns,
        CurrentSystemTime100ns());
    std::uint64_t endedCpu100ns = 0;
    if (cpuStartValid && CurrentThreadCpuTime100ns(endedCpu100ns) &&
        endedCpu100ns >= startedCpu100ns)
    {
        report.cpuTime100ns = endedCpu100ns - startedCpu100ns;
    }
    report.peakWorkingBufferBytes = kMemorySampleBytes;
    return error;
}

DWORD TargetScanWorker::InspectInstrumentationCallback(
    SliceReport& report) noexcept
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto queryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
        ntdll != nullptr
            ? GetProcAddress(ntdll, "NtQueryInformationProcess")
            : nullptr);
    if (queryProcess == nullptr)
    {
        ++report.itemsSkipped;
        return ERROR_SUCCESS;
    }

    InstrumentationCallbackInformation information{};
    ULONG returned = 0;
    const LONG status = queryProcess(
        targetProcess_,
        kProcessInstrumentationCallback,
        &information,
        sizeof(information),
        &returned);
    if (status < 0)
    {
        ++report.itemsSkipped;
        return ERROR_SUCCESS;
    }
    ++report.itemsInspected;
    if (information.Callback == nullptr) return ERROR_SUCCESS;

    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQueryEx(
            targetProcess_,
            information.Callback,
            &memory,
            sizeof(memory)) != sizeof(memory))
    {
        ++report.itemsSkipped;
        return ERROR_SUCCESS;
    }
    if (memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE &&
        IsExecutableProtection(memory.Protect))
    {
        return ERROR_SUCCESS;
    }
    return PublishObservation(
        OAC_V5_RULE_INSTRUMENTATION_CALLBACK,
        OAC_V5_OBSERVATION_HIGH,
        OAC_V5_CATEGORY_DEBUGGER,
        0,
        reinterpret_cast<ULONGLONG>(information.Callback),
        (static_cast<ULONGLONG>(memory.Type) << 32) | memory.Protect,
        L"Target process instrumentation callback points outside executable image-backed memory");
}

DWORD TargetScanWorker::InspectNextThread(
    const ScanSliceBudget& budget,
    ScanSliceProgress& progress,
    SliceReport& report) noexcept
{
    if (threadSweepComplete_ ||
        !CanInspectThread(budget, progress, CurrentUnbiasedTime100ns()))
    {
        return ERROR_SUCCESS;
    }
    if (CancellationRequested()) return ERROR_OPERATION_ABORTED;

    const HANDLE rawSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (rawSnapshot == INVALID_HANDLE_VALUE)
    {
        ++report.itemsSkipped;
        ++report.threadsSkipped;
        return ERROR_SUCCESS;
    }

    DWORD candidate = 0;
    bool enumerationComplete = true;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(rawSnapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID == targetProcessId_ &&
                entry.th32ThreadID > lastThreadId_ &&
                (candidate == 0 || entry.th32ThreadID < candidate))
            {
                candidate = entry.th32ThreadID;
            }
        } while (Thread32Next(rawSnapshot, &entry));
        enumerationComplete = GetLastError() == ERROR_NO_MORE_FILES;
    }
    else
        enumerationComplete = GetLastError() == ERROR_NO_MORE_FILES;
    CloseHandle(rawSnapshot);

    if (candidate == 0)
    {
        if (enumerationComplete)
        {
            threadSweepComplete_ = true;
            lastThreadId_ = 0;
        }
        else
        {
            ++report.itemsSkipped;
            ++report.threadsSkipped;
        }
        return ERROR_SUCCESS;
    }
    lastThreadId_ = candidate;
    ++progress.threadsInspected;

    HANDLE thread = nullptr;
    DWORD fatalError = ERROR_SUCCESS;
    if (!OpenTargetThread(candidate, thread, fatalError))
    {
        if (fatalError != ERROR_SUCCESS) return fatalError;
        ++report.itemsSkipped;
        ++report.threadsSkipped;
        return ERROR_SUCCESS;
    }

    ++report.threadsInspected;
    ++report.itemsInspected;
    bool startOutsideImage = false;
    ULONGLONG startAddressValue = 0;
    ULONGLONG startMemoryState = 0;
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto queryThread = reinterpret_cast<NtQueryInformationThreadFn>(
        ntdll != nullptr
            ? GetProcAddress(ntdll, "NtQueryInformationThread")
            : nullptr);
    if (queryThread != nullptr)
    {
        void* startAddress = nullptr;
        ULONG returned = 0;
        if (queryThread(
                thread,
                kThreadQuerySetWin32StartAddress,
                static_cast<void*>(&startAddress),
                sizeof(startAddress),
                &returned) >= 0 && startAddress != nullptr)
        {
            MEMORY_BASIC_INFORMATION memory{};
            if (VirtualQueryEx(
                    targetProcess_,
                    startAddress,
                    &memory,
                    sizeof(memory)) == sizeof(memory))
            {
                startOutsideImage = memory.State != MEM_COMMIT ||
                    memory.Type != MEM_IMAGE ||
                    !IsExecutableProtection(memory.Protect);
                startAddressValue = reinterpret_cast<ULONGLONG>(startAddress);
                startMemoryState =
                    (static_cast<ULONGLONG>(memory.Type) << 32) |
                    memory.Protect;
            }
            else
            {
                ++report.itemsSkipped;
            }
        }
        else
        {
            ++report.itemsSkipped;
        }
    }
    else
    {
        ++report.itemsSkipped;
    }

    if (CancellationRequested())
    {
        CloseHandle(thread);
        return ERROR_OPERATION_ABORTED;
    }

    oac::ScopedThreadSuspension suspension(thread);
    if (!suspension.Active())
    {
        ++report.itemsSkipped;
        ++report.threadsSkipped;
        CloseHandle(thread);
        return ERROR_SUCCESS;
    }

    bool instructionOutsideImage = false;
    bool debugRegistersEnabled = false;
    bool stackRegionUnexpected = false;
    ULONGLONG instructionAddress = 0;
    ULONGLONG instructionMemoryState = 0;
    ULONGLONG debugAddress = 0;
    ULONGLONG debugControl = 0;
    ULONGLONG stackAddress = 0;
    ULONGLONG stackMemoryState = 0;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &context))
    {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQueryEx(
                targetProcess_,
                reinterpret_cast<const void*>(context.Rip),
                &memory,
                sizeof(memory)) == sizeof(memory))
        {
            instructionOutsideImage = memory.State != MEM_COMMIT ||
                memory.Type != MEM_IMAGE ||
                !IsExecutableProtection(memory.Protect);
            instructionAddress = context.Rip;
            instructionMemoryState =
                (static_cast<ULONGLONG>(memory.Type) << 32) |
                memory.Protect;
        }
        else
        {
            ++report.itemsSkipped;
        }
        if (context.Rsp != 0 && VirtualQueryEx(
                targetProcess_,
                reinterpret_cast<const void*>(context.Rsp),
                &memory,
                sizeof(memory)) == sizeof(memory))
        {
            stackRegionUnexpected = !IsExpectedThreadStackRegion(
                memory.State, memory.Type, memory.Protect);
            stackAddress = context.Rsp;
            stackMemoryState =
                (static_cast<ULONGLONG>(memory.Type) << 32) |
                memory.Protect;
        }
        else
        {
            ++report.itemsSkipped;
        }
        debugRegistersEnabled = (context.Dr7 & 0xFFULL) != 0 ||
            (context.Dr7 & (1ULL << 13)) != 0;
        debugAddress = context.Dr0 != 0 ? context.Dr0
            : (context.Dr1 != 0 ? context.Dr1
                : (context.Dr2 != 0 ? context.Dr2 : context.Dr3));
        debugControl = context.Dr7;
    }
    else
    {
        ++report.itemsSkipped;
        ++report.threadsSkipped;
    }

    const DWORD resumeError = suspension.Resume();
    report.longestSuspension100ns = (std::max)(
        report.longestSuspension100ns,
        suspension.Duration100ns());
    if (resumeError != ERROR_SUCCESS &&
        WaitForSingleObject(thread, 0) != WAIT_OBJECT_0)
    {
        CloseHandle(thread);
        return resumeError;
    }
    CloseHandle(thread);
    DWORD observationError = ERROR_SUCCESS;
    if (startOutsideImage)
    {
        observationError = PublishObservation(
            OAC_V5_RULE_THREAD_OUTSIDE_IMAGE,
            OAC_V5_OBSERVATION_HIGH,
            OAC_V5_CATEGORY_THREAD,
            candidate,
            startAddressValue,
            startMemoryState,
            L"Target thread starts outside executable image-backed memory");
    }
    if (observationError == ERROR_SUCCESS && instructionOutsideImage)
    {
        observationError = PublishObservation(
            OAC_V5_RULE_THREAD_OUTSIDE_IMAGE,
            OAC_V5_OBSERVATION_HIGH,
            OAC_V5_CATEGORY_THREAD,
            candidate,
            instructionAddress,
            instructionMemoryState,
            L"Target thread instruction pointer is outside executable image-backed memory");
    }
    if (observationError == ERROR_SUCCESS && debugRegistersEnabled)
    {
        observationError = PublishObservation(
            OAC_V5_RULE_THREAD_DEBUG_REGISTERS,
            OAC_V5_OBSERVATION_CRITICAL,
            OAC_V5_CATEGORY_DEBUGGER,
            candidate,
            debugAddress,
            debugControl,
            L"Target thread has enabled hardware debug registers");
    }
    if (observationError == ERROR_SUCCESS && stackRegionUnexpected)
    {
        observationError = PublishObservation(
            OAC_V5_RULE_THREAD_STACK_ANOMALY,
            OAC_V5_OBSERVATION_HIGH,
            OAC_V5_CATEGORY_THREAD,
            candidate,
            stackAddress,
            stackMemoryState,
            L"Target thread stack pointer is outside committed private writable memory");
    }
    if (observationError != ERROR_SUCCESS) return observationError;
    return CancellationRequested()
        ? ERROR_OPERATION_ABORTED
        : ERROR_SUCCESS;
}

bool TargetScanWorker::OpenTargetThread(
    DWORD threadId,
    HANDLE& thread,
    DWORD& fatalError) noexcept
{
    thread = nullptr;
    fatalError = ERROR_SUCCESS;
    if (!ImpersonateLoggedOnUser(targetUserToken_))
    {
        fatalError = GetLastError();
        if (fatalError == ERROR_SUCCESS) fatalError = ERROR_CANNOT_IMPERSONATE;
        return false;
    }

    thread = OpenThread(
        THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT |
            THREAD_SUSPEND_RESUME | SYNCHRONIZE,
        FALSE,
        threadId);
    if (!RevertToSelf())
    {
        fatalError = GetLastError();
        if (fatalError == ERROR_SUCCESS) fatalError = ERROR_CANNOT_IMPERSONATE;
        if (thread != nullptr)
        {
            CloseHandle(thread);
            thread = nullptr;
        }
        return false;
    }
    return thread != nullptr;
}

DWORD TargetScanWorker::InspectMemory(
    const ScanSliceBudget& budget,
    ScanSliceProgress& progress,
    SliceReport& report) noexcept
{
    if (memorySweepComplete_) return ERROR_SUCCESS;
    std::array<std::byte, kMemorySampleBytes> sample{};

    while (CanInspectMemory(budget, progress, CurrentUnbiasedTime100ns()))
    {
        if (CancellationRequested()) return ERROR_OPERATION_ABORTED;
        ++progress.regionAttempts;

        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQueryEx(
                targetProcess_,
                reinterpret_cast<const void*>(nextMemoryAddress_),
                &memory,
                sizeof(memory)) == 0)
        {
            ++report.itemsSkipped;
            const std::uintptr_t next = nextMemoryAddress_ + pageSize_;
            if (next <= nextMemoryAddress_ || next > maximumMemoryAddress_)
            {
                memorySweepComplete_ = true;
                break;
            }
            nextMemoryAddress_ = next;
            continue;
        }

        const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(
            memory.BaseAddress);
        const std::uintptr_t next = base + memory.RegionSize;
        if (next <= base)
        {
            memorySweepComplete_ = true;
            break;
        }

        ++report.memoryRegions;
        ++report.itemsInspected;
        if (memory.State == MEM_COMMIT &&
            IsExecutableProtection(memory.Protect))
        {
            DWORD observationError = ERROR_SUCCESS;
            const ULONGLONG memoryState =
                (static_cast<ULONGLONG>(memory.Type) << 32) |
                memory.Protect;
            if (IsWritableExecutableProtection(memory.Protect))
            {
                observationError = PublishObservation(
                    OAC_V5_RULE_WRITABLE_EXECUTABLE_MEMORY,
                    OAC_V5_OBSERVATION_CRITICAL,
                    OAC_V5_CATEGORY_MEMORY,
                    0,
                    base,
                    memoryState,
                    L"Target contains writable executable memory");
            }
            else if (memory.Type != MEM_IMAGE)
            {
                observationError = PublishObservation(
                    OAC_V5_RULE_EXECUTABLE_NONIMAGE_MEMORY,
                    OAC_V5_OBSERVATION_HIGH,
                    OAC_V5_CATEGORY_MEMORY,
                    0,
                    base,
                    memoryState,
                    L"Target contains executable memory without image backing");
            }
            if (observationError != ERROR_SUCCESS) return observationError;
        }
        if (memory.State == MEM_COMMIT && memory.Type != MEM_IMAGE &&
            IsExecutableProtection(memory.Protect) &&
            CanReadProtection(memory.Protect))
        {
            const std::uint64_t remaining = budget.byteLimit - progress.bytesRead;
            const SIZE_T requested = static_cast<SIZE_T>((std::min)(
                (std::min)(
                    static_cast<std::uint64_t>(memory.RegionSize),
                    static_cast<std::uint64_t>(sample.size())),
                remaining));
            if (requested != 0)
            {
                SIZE_T received = 0;
                const BOOL read = ReadProcessMemory(
                    targetProcess_,
                    memory.BaseAddress,
                    sample.data(),
                    requested,
                    &received);
                if (received != 0)
                {
                    progress.bytesRead += received;
                    report.bytesRead += received;
                }
                if (!read && received == 0) ++report.itemsSkipped;
                if (received != 0 &&
                    ContainsPortableExecutable(sample.data(), received))
                {
                    const DWORD observationError = PublishObservation(
                        OAC_V5_RULE_UNBACKED_PE_IMAGE,
                        OAC_V5_OBSERVATION_HIGH,
                        OAC_V5_CATEGORY_MEMORY,
                        0,
                        base,
                        (static_cast<ULONGLONG>(memory.Type) << 32) |
                            memory.Protect,
                        L"Target contains a PE image in executable memory without image backing");
                    if (observationError != ERROR_SUCCESS)
                        return observationError;
                }
                const std::size_t syscallOffset = FindDirectSyscallStub(
                    sample.data(), received);
                if (syscallOffset != kDirectSyscallStubNotFound)
                {
                    const DWORD observationError = PublishObservation(
                        OAC_V5_RULE_DIRECT_SYSCALL_STUB,
                        OAC_V5_OBSERVATION_HIGH,
                        OAC_V5_CATEGORY_MEMORY,
                        0,
                        base + syscallOffset,
                        (static_cast<ULONGLONG>(memory.Type) << 32) |
                            memory.Protect,
                        L"Target contains a direct system-call stub in executable memory without image backing");
                    if (observationError != ERROR_SUCCESS)
                        return observationError;
                }
            }
        }

        if (next > maximumMemoryAddress_)
        {
            memorySweepComplete_ = true;
            break;
        }
        nextMemoryAddress_ = next;
    }
    return ERROR_SUCCESS;
}

DWORD TargetScanWorker::PublishObservation(
    OAC_V5_RULE_ID ruleId,
    OAC_V5_OBSERVATION_SEVERITY severity,
    OAC_V5_CATEGORY category,
    ULONGLONG threadId,
    ULONGLONG address,
    ULONGLONG auxiliary,
    const wchar_t* text) noexcept
{
    if (!OacV5RuleIdValid(ruleId) ||
        !OacV5ObservationSeverityValid(severity) ||
        !OacV5CategoryValid(category) || text == nullptr || text[0] == L'\0')
    {
        return ERROR_INVALID_PARAMETER;
    }
    for (std::size_t index = 0; index != observedKeyCount_; ++index)
    {
        const ObservationKey& key = observedKeys_[index];
        if (key.RuleId == ruleId && key.ThreadId == threadId &&
            key.Address == address)
        {
            return ERROR_SUCCESS;
        }
    }
    if (observedKeyCount_ == observedKeys_.size())
        return ERROR_BUFFER_OVERFLOW;

    TargetObservation observation{};
    observation.RuleId = ruleId;
    observation.Severity = severity;
    observation.Category = category;
    observation.ProcessId = targetProcessId_;
    observation.ThreadId = threadId;
    observation.Address = address;
    observation.Auxiliary = auxiliary;
    if (FAILED(StringCchCopyW(
            observation.Text,
            ARRAYSIZE(observation.Text),
            text)))
    {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    AcquireSRWLockExclusive(&observationLock_);
    if (observationCount_ == observations_.size())
    {
        ReleaseSRWLockExclusive(&observationLock_);
        return ERROR_BUFFER_OVERFLOW;
    }
    observations_[observationWrite_] = observation;
    observationWrite_ = (observationWrite_ + 1) % observations_.size();
    ++observationCount_;
    ReleaseSRWLockExclusive(&observationLock_);

    observedKeys_[observedKeyCount_++] = {ruleId, threadId, address};
    return ERROR_SUCCESS;
}

void TargetScanWorker::PublishReport(const SliceReport& report) noexcept
{
    AcquireSRWLockExclusive(&metricsLock_);
    if (report.error == ERROR_SUCCESS)
    {
        AddSaturating(metrics_.SlicesCompleted, 1);
        if (report.sweepCompleted) AddSaturating(metrics_.SweepsCompleted, 1);
        metrics_.LastOutcome = report.sweepCompleted
            ? OAC_IPC_SCAN_OUTCOME_SWEEP_COMPLETED
            : OAC_IPC_SCAN_OUTCOME_PARTIAL;
    }
    else if (report.error == ERROR_OPERATION_ABORTED)
    {
        AddSaturating(metrics_.SlicesCancelled, 1);
        metrics_.LastOutcome = OAC_IPC_SCAN_OUTCOME_CANCELLED;
    }
    else
    {
        AddSaturating(metrics_.SlicesFailed, 1);
        metrics_.LastOutcome = OAC_IPC_SCAN_OUTCOME_FAILED;
    }

    AddSaturating(metrics_.MemoryRegionsInspected, report.memoryRegions);
    AddSaturating(metrics_.MemoryBytesRead, report.bytesRead);
    AddSaturating(metrics_.ThreadsInspected, report.threadsInspected);
    AddSaturating(metrics_.ThreadsSkipped, report.threadsSkipped);
    metrics_.MaximumSliceDuration100ns = (std::max)(
        metrics_.MaximumSliceDuration100ns,
        report.duration100ns);
    metrics_.MaximumThreadSuspension100ns = (std::max)(
        metrics_.MaximumThreadSuspension100ns,
        report.longestSuspension100ns);
    metrics_.LastStartTime100ns = report.startTime100ns;
    metrics_.LastEndTime100ns = report.endTime100ns;
    metrics_.LastCpuTime100ns = report.cpuTime100ns;
    metrics_.LastBytesRead = report.bytesRead;
    metrics_.LastItemsInspected = report.itemsInspected;
    metrics_.LastItemsSkipped = report.itemsSkipped;
    metrics_.PeakWorkingBufferBytes = (std::max)(
        metrics_.PeakWorkingBufferBytes,
        report.peakWorkingBufferBytes);
    metrics_.LastError = report.error;
    ReleaseSRWLockExclusive(&metricsLock_);
}

void TargetScanWorker::PublishFailure(DWORD error) noexcept
{
    if (error == ERROR_SUCCESS) error = ERROR_GEN_FAILURE;
    (void)InterlockedCompareExchange(
        &failureError_,
        static_cast<LONG>(error),
        ERROR_SUCCESS);
    AcquireSRWLockExclusive(&metricsLock_);
    if (metrics_.LastStartTime100ns == 0)
    {
        metrics_.LastStartTime100ns = CurrentSystemTime100ns();
        metrics_.LastEndTime100ns = metrics_.LastStartTime100ns;
    }
    metrics_.State = OAC_IPC_SCAN_FAILED;
    metrics_.LastOutcome = OAC_IPC_SCAN_OUTCOME_FAILED;
    metrics_.LastError = error;
    ReleaseSRWLockExclusive(&metricsLock_);
    if (failureEvent_ != nullptr) (void)SetEvent(failureEvent_);
}

void TargetScanWorker::PublishStopped(bool pendingCancelled) noexcept
{
    AcquireSRWLockExclusive(&metricsLock_);
    if (pendingCancelled) AddSaturating(metrics_.SlicesCancelled, 1);
    if (metrics_.State != OAC_IPC_SCAN_FAILED)
        metrics_.State = OAC_IPC_SCAN_STOPPED;
    ReleaseSRWLockExclusive(&metricsLock_);
}

bool TargetScanWorker::CancellationRequested() const noexcept
{
    return WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0 ||
        WaitForSingleObject(cancelEvent_, 0) == WAIT_OBJECT_0 ||
        (targetProcess_ != nullptr &&
         WaitForSingleObject(targetProcess_, 0) == WAIT_OBJECT_0);
}
} // namespace oac
