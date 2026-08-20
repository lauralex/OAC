#pragma once

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include "..\shared\oac_ipc.h"
#include "..\shared\protocol\oac_v5.h"

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
inline constexpr std::size_t kTargetObservationCapacity = 64;
inline constexpr std::size_t kDirectSyscallStubNotFound =
    static_cast<std::size_t>(-1);

[[nodiscard]] constexpr bool ContainsPortableExecutable(
    const std::byte* bytes,
    std::size_t length) noexcept
{
    constexpr std::size_t offsetField = 0x3c;
    if (bytes == nullptr || length < offsetField + sizeof(std::uint32_t) ||
        std::to_integer<unsigned char>(bytes[0]) != 'M' ||
        std::to_integer<unsigned char>(bytes[1]) != 'Z')
    {
        return false;
    }
    std::uint32_t signatureOffset = 0;
    for (std::size_t index = 0; index != sizeof(signatureOffset); ++index)
    {
        signatureOffset |= static_cast<std::uint32_t>(
            std::to_integer<unsigned char>(bytes[offsetField + index])) <<
            (index * 8);
    }
    return signatureOffset <= length &&
        length - signatureOffset >= sizeof(std::uint32_t) &&
        std::to_integer<unsigned char>(bytes[signatureOffset]) == 'P' &&
        std::to_integer<unsigned char>(bytes[signatureOffset + 1]) == 'E' &&
        bytes[signatureOffset + 2] == std::byte{0} &&
        bytes[signatureOffset + 3] == std::byte{0};
}

[[nodiscard]] constexpr std::size_t FindDirectSyscallStub(
    const std::byte* bytes,
    std::size_t length) noexcept
{
    if (bytes == nullptr) return kDirectSyscallStubNotFound;
    for (std::size_t offset = 0; offset + 11 <= length; ++offset)
    {
        const auto value = [bytes, offset](std::size_t index) constexpr
        {
            return std::to_integer<unsigned char>(bytes[offset + index]);
        };
        if (value(0) == 0x4C && value(1) == 0x8B && value(2) == 0xD1 &&
            value(3) == 0xB8 && value(8) == 0x0F && value(9) == 0x05 &&
            value(10) == 0xC3)
        {
            return offset;
        }
    }
    return kDirectSyscallStubNotFound;
}

[[nodiscard]] constexpr bool IsExpectedThreadStackRegion(
    DWORD state,
    DWORD type,
    DWORD protection) noexcept
{
    const DWORD base = protection & 0xFFu;
    return state == MEM_COMMIT && type == MEM_PRIVATE &&
        (protection & PAGE_NOACCESS) == 0 &&
        (base == PAGE_READWRITE || base == PAGE_WRITECOPY);
}

[[nodiscard]] constexpr bool IsWritableExecutableProtection(
    DWORD protection) noexcept
{
    const DWORD base = protection & 0xFFu;
    return base == PAGE_EXECUTE_READWRITE ||
        base == PAGE_EXECUTE_WRITECOPY;
}

struct TargetObservation
{
    OAC_V5_RULE_ID RuleId = 0;
    OAC_V5_OBSERVATION_SEVERITY Severity = OAC_V5_OBSERVATION_INFO;
    OAC_V5_CATEGORY Category = OAC_V5_CATEGORY_GENERAL;
    ULONGLONG ProcessId = 0;
    ULONGLONG ThreadId = 0;
    ULONGLONG Address = 0;
    ULONGLONG Auxiliary = 0;
    wchar_t Text[OAC_V5_MAX_EVENT_TEXT]{};
};

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
    bool TakeObservation(TargetObservation& observation) noexcept;

    [[nodiscard]] HANDLE FailureEvent() const noexcept;
    [[nodiscard]] DWORD FailureError() const noexcept;

private:
    struct ObservationKey
    {
        OAC_V5_RULE_ID RuleId = 0;
        ULONGLONG ThreadId = 0;
        ULONGLONG Address = 0;
    };

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
    DWORD InspectInstrumentationCallback(SliceReport& report) noexcept;
    DWORD InspectMemory(
        const ScanSliceBudget& budget,
        ScanSliceProgress& progress,
        SliceReport& report) noexcept;
    bool OpenTargetThread(
        DWORD threadId,
        HANDLE& thread,
        DWORD& fatalError) noexcept;
    DWORD PublishObservation(
        OAC_V5_RULE_ID ruleId,
        OAC_V5_OBSERVATION_SEVERITY severity,
        OAC_V5_CATEGORY category,
        ULONGLONG threadId,
        ULONGLONG address,
        ULONGLONG auxiliary,
        const wchar_t* text) noexcept;
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
    mutable SRWLOCK observationLock_ = SRWLOCK_INIT;
    OAC_IPC_SCAN_METRICS metrics_{};
    std::array<TargetObservation, kTargetObservationCapacity> observations_{};
    std::array<ObservationKey, kTargetObservationCapacity> observedKeys_{};
    std::size_t observationRead_ = 0;
    std::size_t observationWrite_ = 0;
    std::size_t observationCount_ = 0;
    std::size_t observedKeyCount_ = 0;
    std::uintptr_t nextMemoryAddress_ = 0;
    std::uintptr_t maximumMemoryAddress_ = 0;
    std::uint32_t pageSize_ = 4096;
    DWORD lastThreadId_ = 0;
    bool memorySweepComplete_ = false;
    bool threadSweepComplete_ = false;
};
} // namespace oac
