#include "target_scanner.hpp"

#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>

#include "..\shared\oac_thread_suspension.hpp"

namespace
{
using NtQueryInformationThreadFn = LONG(NTAPI*)(
    HANDLE,
    LONG,
    void*,
    ULONG,
    ULONG*);

constexpr LONG kThreadQuerySetWin32StartAddress = 9;

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
        : InspectNextThread(budget, progress, report);
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
    }
    CloseHandle(rawSnapshot);

    if (candidate == 0)
    {
        threadSweepComplete_ = true;
        lastThreadId_ = 0;
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
            (void)VirtualQueryEx(
                targetProcess_,
                startAddress,
                &memory,
                sizeof(memory));
        }
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

    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &context))
    {
        MEMORY_BASIC_INFORMATION memory{};
        (void)VirtualQueryEx(
            targetProcess_,
            reinterpret_cast<const void*>(context.Rip),
            &memory,
            sizeof(memory));
        (void)VirtualQueryEx(
            targetProcess_,
            reinterpret_cast<const void*>(context.Rsp),
            &memory,
            sizeof(memory));
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
