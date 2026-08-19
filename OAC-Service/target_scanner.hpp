#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

#include "..\shared\oac_ipc.h"

namespace oac
{
inline constexpr std::uint64_t kHundredNanosecondsPerMillisecond = 10000;
inline constexpr DWORD kHealthIntervalMilliseconds = 250;
inline constexpr DWORD kHealthDelayBudgetMilliseconds = 500;
inline constexpr DWORD kScanSliceBudgetMilliseconds = 20;
inline constexpr std::uint64_t kScanSliceByteBudget = 64ULL * 1024ULL;
inline constexpr std::uint32_t kScanSliceRegionBudget = 64;
inline constexpr std::uint32_t kScanSliceThreadBudget = 1;
inline constexpr std::size_t kMemorySampleBytes = 4096;

struct ScanSliceBudget
{
    std::uint64_t deadline100ns = 0;
    std::uint64_t byteLimit = kScanSliceByteBudget;
    std::uint32_t regionLimit = kScanSliceRegionBudget;
    std::uint32_t threadLimit = kScanSliceThreadBudget;
};

struct ScanSliceProgress
{
    std::uint64_t bytesRead = 0;
    std::uint32_t regionAttempts = 0;
    std::uint32_t threadsInspected = 0;
};

[[nodiscard]] constexpr bool CanInspectMemory(
    const ScanSliceBudget& budget,
    const ScanSliceProgress& progress,
    std::uint64_t now100ns) noexcept
{
    return now100ns < budget.deadline100ns &&
        progress.bytesRead < budget.byteLimit &&
        progress.regionAttempts < budget.regionLimit;
}

[[nodiscard]] constexpr bool CanInspectThread(
    const ScanSliceBudget& budget,
    const ScanSliceProgress& progress,
    std::uint64_t now100ns) noexcept
{
    return now100ns < budget.deadline100ns &&
        progress.threadsInspected < budget.threadLimit;
}

class TargetScanWorker final
{
public:
    explicit TargetScanWorker(HANDLE stopEvent) noexcept;
    ~TargetScanWorker();

    TargetScanWorker(const TargetScanWorker&) = delete;
    TargetScanWorker& operator=(const TargetScanWorker&) = delete;

    [[nodiscard]] bool Ready() const noexcept;
    DWORD Start(
        HANDLE targetProcess,
        DWORD targetProcessId,
        HANDLE targetUserToken) noexcept;
    DWORD QueueSlice() noexcept;
    DWORD Stop() noexcept;
    void RecordHealthIteration(std::uint64_t delay100ns) noexcept;
    void CopyMetrics(OAC_IPC_SCAN_METRICS& metrics) const noexcept;

    [[nodiscard]] HANDLE FailureEvent() const noexcept;
    [[nodiscard]] DWORD FailureError() const noexcept;

private:
    struct SliceReport
    {
        std::uint64_t startTime100ns = 0;
        std::uint64_t endTime100ns = 0;
        std::uint64_t cpuTime100ns = 0;
        std::uint64_t duration100ns = 0;
        std::uint64_t bytesRead = 0;
        std::uint64_t itemsInspected = 0;
        std::uint64_t itemsSkipped = 0;
        std::uint64_t memoryRegions = 0;
        std::uint64_t threadsInspected = 0;
        std::uint64_t threadsSkipped = 0;
        std::uint64_t longestSuspension100ns = 0;
        std::uint64_t peakWorkingBufferBytes = 0;
        DWORD error = ERROR_SUCCESS;
        bool sweepCompleted = false;
    };

    static DWORD WINAPI ThreadEntry(void* context) noexcept;
    DWORD Run() noexcept;
    DWORD RunSlice(SliceReport& report) noexcept;
    DWORD InspectNextThread(
        const ScanSliceBudget& budget,
        ScanSliceProgress& progress,
        SliceReport& report) noexcept;
    DWORD InspectMemory(
        const ScanSliceBudget& budget,
        ScanSliceProgress& progress,
        SliceReport& report) noexcept;
    bool OpenTargetThread(
        DWORD threadId,
        HANDLE& thread,
        DWORD& fatalError) noexcept;
    void PublishReport(const SliceReport& report) noexcept;
    void PublishFailure(DWORD error) noexcept;
    void PublishStopped(bool pendingCancelled) noexcept;
    [[nodiscard]] bool CancellationRequested() const noexcept;

    HANDLE stopEvent_ = nullptr;
    HANDLE cancelEvent_ = nullptr;
    HANDLE workEvent_ = nullptr;
    HANDLE failureEvent_ = nullptr;
    HANDLE thread_ = nullptr;
    HANDLE targetProcess_ = nullptr;
    HANDLE targetUserToken_ = nullptr;
    DWORD targetProcessId_ = 0;
    volatile LONG pending_ = FALSE;
    volatile LONG started_ = FALSE;
    volatile LONG failureError_ = ERROR_SUCCESS;
    mutable SRWLOCK metricsLock_ = SRWLOCK_INIT;
    OAC_IPC_SCAN_METRICS metrics_{};
    std::uintptr_t nextMemoryAddress_ = 0;
    std::uintptr_t maximumMemoryAddress_ = 0;
    std::uint32_t pageSize_ = 4096;
    DWORD lastThreadId_ = 0;
    bool memorySweepComplete_ = false;
    bool threadSweepComplete_ = false;
};
} // namespace oac
