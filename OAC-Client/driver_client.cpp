#include "scanner.hpp"
#include "..\shared\oac_protocol.h"

#include <memory>
#include <set>
#include <sstream>
#include <string_view>
#include <vector>

namespace
{
class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : handle_(handle) {}
    ~UniqueHandle()
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    HANDLE get() const noexcept { return handle_; }
    explicit operator bool() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

std::wstring LastErrorMessage(DWORD error)
{
    wchar_t* text = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<wchar_t*>(&text),
        0,
        nullptr);
    std::wstring message = length != 0 && text != nullptr
        ? std::wstring(text, length)
        : L"Win32 error " + std::to_wstring(error);
    if (text != nullptr) LocalFree(text);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n'))
        message.pop_back();
    return message;
}

FindingSeverity ConvertSeverity(ULONG value)
{
    switch (value)
    {
    case OacSeverityCritical: return FindingSeverity::Critical;
    case OacSeverityHigh: return FindingSeverity::High;
    case OacSeverityMedium: return FindingSeverity::Medium;
    case OacSeverityLow: return FindingSeverity::Low;
    default: return FindingSeverity::Info;
    }
}

std::wstring ConvertCategory(ULONG value)
{
    static constexpr const wchar_t* names[] =
    {
        L"kernel/general", L"kernel/process", L"kernel/handle", L"kernel/module",
        L"kernel/driver", L"kernel/memory", L"kernel/thread", L"kernel/debugger",
        L"kernel/integrity", L"kernel/virtualization", L"kernel/service",
        L"kernel/device", L"kernel/window", L"kernel/hwid"
    };
    return value < std::size(names) ? names[value] : L"kernel/unknown";
}

bool IsPendingHandleMutation(const OAC_FINDING& finding, const std::wstring& text)
{
    static constexpr std::wstring_view prefix =
        L"Stripped protected-object mutation access pending signed-owner classification:";
    return finding.Category == OacCategoryHandle && text.starts_with(prefix);
}

void AddKernelFinding(
    const OAC_FINDING& finding,
    const std::wstring& text,
    Reporter& reporter)
{
    FindingSeverity severity = ConvertSeverity(finding.Severity);
    std::wstring enrichedText = text;
    if (IsPendingHandleMutation(finding, text))
    {
        const std::wstring path = QueryProcessImagePath(finding.ProcessId);
        if (IsTrustedWindowsImagePath(path))
        {
            severity = FindingSeverity::Low;
            enrichedText += L"; trusted Windows image=" + path;
        }
        else if (path.empty())
        {
            severity = FindingSeverity::Medium;
            enrichedText += L"; requestor image unavailable or already exited";
        }
        else
        {
            severity = FindingSeverity::High;
            enrichedText += L"; untrusted requestor image=" + path;
        }
    }
    reporter.Add(
        severity,
        ConvertCategory(finding.Category),
        enrichedText,
        finding.ProcessId,
        finding.ThreadId,
        finding.Address);
}

bool DrainFindings(HANDLE device, Reporter& reporter)
{
    auto response = std::make_unique<OAC_FINDINGS_RESPONSE>();
    DWORD returned = 0;
    const size_t header = offsetof(OAC_FINDINGS_RESPONSE, Findings);
    for (unsigned attempt = 0; attempt < 1024; ++attempt)
    {
        SecureZeroMemory(response.get(), sizeof(*response));
        returned = 0;
        if (!DeviceIoControl(
                device,
                IOCTL_OAC_GET_FINDINGS,
                nullptr,
                0,
                response.get(),
                sizeof(*response),
                &returned,
                nullptr))
        {
            reporter.Add(FindingSeverity::Medium, L"driver",
                L"Unable to read kernel findings: " + LastErrorMessage(GetLastError()));
            return false;
        }

        const size_t available = returned >= header
            ? (returned - header) / sizeof(OAC_FINDING)
            : 0;
        if (returned < header ||
            response->Version != OAC_PROTOCOL_VERSION ||
            response->Size < header || response->Size > returned ||
            response->Count > OAC_MAX_FINDINGS_PER_READ ||
            response->Count > available ||
            response->Size != header + response->Count * sizeof(OAC_FINDING))
        {
            reporter.Add(FindingSeverity::High, L"driver",
                L"Kernel finding response failed protocol validation");
            return false;
        }

        for (ULONG i = 0; i < response->Count; ++i)
        {
            const auto& finding = response->Findings[i];
            if (finding.Severity > OacSeverityCritical ||
                finding.Category > OacCategoryHwid)
            {
                reporter.Add(FindingSeverity::High, L"driver",
                    L"Kernel finding contained an invalid severity or category");
                return false;
            }
            const std::wstring text(
                finding.Text,
                wcsnlen_s(finding.Text, OAC_MAX_FINDING_TEXT));
            AddKernelFinding(finding, text, reporter);
        }
        if (response->Remaining == 0) return true;
    }

    reporter.Add(FindingSeverity::Medium, L"driver",
        L"Kernel finding drain stopped at its safety iteration limit");
    return false;
}

bool CheckDriverGate(
    const OAC_STATUS_RESPONSE& status,
    const std::wstring& category,
    Reporter& reporter)
{
    if (status.PostStartLoads == 0 && status.DriverGateTrips == 0)
        return true;

    std::wostringstream message;
    message << L"Fail-closed post-start driver-load latch is set: observed="
            << status.PostStartLoads << L", gate-trips="
            << status.DriverGateTrips
            << L". A kernel image loaded after OAC registered its callback; "
               L"renaming, unloading, or deleting loader traces cannot clear this state. "
               L"Restart the demand-start OAC service only after restoring a clean driver set.";
    reporter.Add(FindingSeverity::Critical, category, message.str());
    return false;
}
} // namespace

bool RunDriverScan(const ScanOptions& options, Reporter& reporter)
{
    UniqueHandle device(CreateFileW(
        L"\\\\.\\OAC",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!device)
    {
        reporter.Add(options.deploymentMode == DeploymentMode::Production
                ? FindingSeverity::High : FindingSeverity::Medium,
            L"driver",
            L"OAC driver is unavailable; kernel-only checks were skipped: " +
                LastErrorMessage(GetLastError()));
        return false;
    }

    OAC_CONFIG_REQUEST configuration{};
    configuration.Version = OAC_PROTOCOL_VERSION;
    configuration.Size = sizeof(configuration);
    configuration.ProtectedProcessId = options.targetProcessId;
    configuration.ClientProcessId = GetCurrentProcessId();
    configuration.Flags = OAC_CONFIG_ENABLE_IMAGE_LOG |
        OAC_CONFIG_DRIVER_GATE;
    if (options.targetProcessId != 0)
        configuration.Flags |= OAC_CONFIG_PROTECT_PROCESS;
    DWORD returned = 0;
    if (!DeviceIoControl(
            device.get(),
            IOCTL_OAC_CONFIGURE,
            &configuration,
            sizeof(configuration),
            nullptr,
            0,
            &returned,
            nullptr))
    {
        reporter.Add(FindingSeverity::High, L"driver",
            L"Kernel protection configuration failed: " + LastErrorMessage(GetLastError()));
        return false;
    }

    bool healthy = true;
    OAC_SCAN_REQUEST request{};
    request.Version = OAC_PROTOCOL_VERSION;
    request.Size = sizeof(request);
    if (options.verboseHandles) request.Flags |= OAC_SCAN_VERBOSE_HANDLES;
    if (options.privateKernelTraces) request.Flags |= OAC_SCAN_PRIVATE_KERNEL_TRACES;
    if (!DeviceIoControl(
            device.get(),
            IOCTL_OAC_RUN_KERNEL_SCAN,
            &request,
            sizeof(request),
            nullptr,
            0,
            &returned,
            nullptr))
    {
        healthy = false;
        reporter.Add(FindingSeverity::High, L"driver",
            L"Kernel scan failed: " + LastErrorMessage(GetLastError()));
    }

    std::vector<std::byte> cpuBuffer(size_t{64} * 1024);
    bool cpuCaptured = false;
    DWORD cpuError = ERROR_SUCCESS;
    for (unsigned attempt = 0; attempt < 4; ++attempt)
    {
        returned = 0;
        if (DeviceIoControl(
                device.get(),
                IOCTL_OAC_CPU_SNAPSHOT,
                nullptr,
                0,
                cpuBuffer.data(),
                static_cast<DWORD>(cpuBuffer.size()),
                &returned,
                nullptr))
        {
            cpuCaptured = true;
            break;
        }
        cpuError = GetLastError();
        if ((cpuError != ERROR_INSUFFICIENT_BUFFER && cpuError != ERROR_MORE_DATA) ||
            cpuBuffer.size() >= size_t{1024} * 1024) break;
        cpuBuffer.resize(cpuBuffer.size() * 2);
    }

    if (cpuCaptured)
    {
        const auto* response = reinterpret_cast<const OAC_CPU_RESPONSE*>(cpuBuffer.data());
        const size_t header = offsetof(OAC_CPU_RESPONSE, Records);
        const size_t available = returned >= header
            ? (returned - header) / sizeof(OAC_CPU_RECORD)
            : 0;
        if (returned >= header &&
            response->Version == OAC_PROTOCOL_VERSION &&
            response->Size >= header && response->Size <= returned &&
            response->Count <= available && response->Count <= response->Capacity &&
            response->Size == header + response->Count * sizeof(OAC_CPU_RECORD))
        {
            std::set<ULONG> processorIndexes;
            ULONG platformAnomalies = 0;
            const OAC_CPU_RECORD* reference = response->Count != 0
                ? &response->Records[0]
                : nullptr;
            for (ULONG i = 0; i < response->Count; ++i)
            {
                const auto& cpu = response->Records[i];
                if (!processorIndexes.insert(cpu.ProcessorIndex).second)
                {
                    ++platformAnomalies;
                    reporter.Add(FindingSeverity::High, L"kernel/cpu",
                        L"CPU snapshot contains a duplicate processor index " +
                            std::to_wstring(cpu.ProcessorIndex));
                }
                if ((cpu.Dr7 & 0xFFULL) != 0 || (cpu.Dr7 & (1ULL << 13)) != 0)
                {
                    std::wostringstream message;
                    message << L"CPU " << cpu.ProcessorIndex
                            << L" has enabled hardware breakpoints or DR7.GD (DR0-3=0x"
                            << std::hex << cpu.Dr0 << L"/0x" << cpu.Dr1
                            << L"/0x" << cpu.Dr2 << L"/0x" << cpu.Dr3
                            << L", DR7=0x" << cpu.Dr7 << L", DR6=0x" << cpu.Dr6 << L")";
                    reporter.Add(FindingSeverity::High, L"kernel/debugger",
                        message.str());
                }

                constexpr ULONGLONG requiredCr0 = (1ULL << 0) | (1ULL << 16) |
                    (1ULL << 31);
                constexpr ULONGLONG requiredEfer = (1ULL << 0) | (1ULL << 8) |
                    (1ULL << 10);
                if ((cpu.Cr0 & requiredCr0) != requiredCr0 ||
                    (cpu.Cr4 & (1ULL << 5)) == 0 ||
                    (cpu.Efer & requiredEfer) != requiredEfer || cpu.Lstar == 0)
                {
                    ++platformAnomalies;
                    reporter.Add(FindingSeverity::Critical, L"kernel/integrity",
                        L"CPU " + std::to_wstring(cpu.ProcessorIndex) +
                            L" has invalid long-mode control or syscall state");
                }
                if ((cpu.CpuidExtended1Edx & (1UL << 20)) != 0 &&
                    (cpu.Efer & (1ULL << 11)) == 0)
                {
                    ++platformAnomalies;
                    reporter.Add(FindingSeverity::High, L"kernel/integrity",
                        L"CPU " + std::to_wstring(cpu.ProcessorIndex) +
                            L" advertises NX while EFER.NXE is clear");
                }

                if ((cpu.Flags & OAC_CPU_FLAG_HYPERVISOR_PRESENT) != 0)
                {
                    bool printable = false;
                    bool invalidCharacter = false;
                    for (size_t character = 0; character < 12; ++character)
                    {
                        const UCHAR value = cpu.HypervisorVendor[character];
                        if (value == 0) continue;
                        printable = true;
                        if (value < 0x20 || value > 0x7e)
                        {
                            invalidCharacter = true;
                            continue;
                        }
                    }
                    if (!printable || invalidCharacter ||
                        cpu.HypervisorMaximumLeaf < 0x40000000UL ||
                        cpu.HypervisorMaximumLeaf > 0x4000FFFFUL)
                    {
                        ++platformAnomalies;
                        reporter.Add(FindingSeverity::High, L"kernel/virtualization",
                            L"CPU " + std::to_wstring(cpu.ProcessorIndex) +
                                L" has an inconsistent hypervisor CPUID namespace");
                    }
                }

                if (reference != nullptr && i != 0 &&
                    (cpu.Lstar != reference->Lstar || cpu.Cstar != reference->Cstar ||
                     cpu.Star != reference->Star || cpu.Fmask != reference->Fmask ||
                     cpu.Cr0 != reference->Cr0 || cpu.Cr4 != reference->Cr4 ||
                     cpu.Efer != reference->Efer ||
                     (cpu.Flags & OAC_CPU_FLAG_HYPERVISOR_PRESENT) !=
                        (reference->Flags & OAC_CPU_FLAG_HYPERVISOR_PRESENT) ||
                     cpu.HypervisorMaximumLeaf != reference->HypervisorMaximumLeaf ||
                     std::memcmp(cpu.HypervisorVendor,
                        reference->HypervisorVendor, 12) != 0))
                {
                    ++platformAnomalies;
                    reporter.Add(FindingSeverity::High, L"kernel/integrity",
                        L"CPU " + std::to_wstring(cpu.ProcessorIndex) +
                            L" platform state is inconsistent with CPU " +
                            std::to_wstring(reference->ProcessorIndex));
                }
            }
            const DWORD expectedProcessors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
            if (expectedProcessors != 0 && response->Count != expectedProcessors)
                reporter.Add(FindingSeverity::Low, L"kernel/cpu",
                    L"CPU snapshot count changed during collection (captured " +
                        std::to_wstring(response->Count) + L", active " +
                        std::to_wstring(expectedProcessors) + L")");
            reporter.Add(FindingSeverity::Info, L"kernel/cpu",
                L"Captured CR0/3/4, DR0-3/6/7, EFER/syscall MSRs, IDTR/GDTR, and CPUID from " +
                    std::to_wstring(response->Count) + L" logical processors; anomalies=" +
                    std::to_wstring(platformAnomalies));
        }
        else
        {
            healthy = false;
            reporter.Add(FindingSeverity::High, L"driver",
                L"CPU snapshot response failed protocol validation");
        }
    }
    else
    {
        healthy = false;
        reporter.Add(FindingSeverity::Medium, L"driver",
            L"CPU snapshot failed: " + LastErrorMessage(cpuError));
    }

    OAC_STATUS_RESPONSE status{};
    if (DeviceIoControl(
            device.get(),
            IOCTL_OAC_GET_STATUS,
            nullptr,
            0,
            &status,
            sizeof(status),
            &returned,
            nullptr) && returned >= sizeof(status) &&
        status.Version == OAC_PROTOCOL_VERSION &&
        status.Size == sizeof(status))
    {
        constexpr ULONG requiredCapabilities = OAC_CAP_HANDLE_PROTECTION |
            OAC_CAP_IMAGE_TELEMETRY | OAC_CAP_PROCESS_CROSS_VIEW |
            OAC_CAP_MODULE_CROSS_VIEW | OAC_CAP_HANDLE_SCAN |
            OAC_CAP_KERNEL_INTEGRITY | OAC_CAP_SYSTEM_THREAD_SCAN |
            OAC_CAP_CPU_SNAPSHOT | OAC_CAP_CPU_PLATFORM_STATE |
            OAC_CAP_DRIVER_SELF_INTEGRITY | OAC_CAP_IMPORT_INTEGRITY |
            OAC_CAP_VIRTUALIZATION_STATE | OAC_CAP_DRIVER_GATE;
        std::wostringstream message;
        message << L"Driver capabilities=0x" << std::hex << status.Capabilities
                << L", findings dropped=" << std::dec << status.FindingsDropped
                << L", post-start driver loads=" << status.PostStartLoads
                << L", load-gate trips=" << status.DriverGateTrips;
        reporter.Add(
            status.FindingsDropped == 0 ? FindingSeverity::Info :
                (options.deploymentMode == DeploymentMode::Production
                    ? FindingSeverity::Critical : FindingSeverity::High),
            L"driver",
            message.str());
        if (status.FindingsDropped != 0) healthy = false;
        if (!CheckDriverGate(status, L"driver/load-gate", reporter))
            healthy = false;
        if ((status.Capabilities & requiredCapabilities) != requiredCapabilities)
        {
            healthy = false;
            reporter.Add(FindingSeverity::High, L"driver",
                L"Driver is missing one or more required stable capabilities");
        }
        if (status.ProtectedProcessId != options.targetProcessId ||
            status.ClientProcessId != GetCurrentProcessId())
        {
            healthy = false;
            reporter.Add(FindingSeverity::High, L"driver",
                L"Driver protection identity changed before scan completion");
        }
        if ((status.ConfigurationFlags &
             OAC_CONFIG_DRIVER_GATE) == 0)
        {
            healthy = false;
            reporter.Add(FindingSeverity::Critical, L"driver/load-gate",
                L"Kernel driver-load gate is not armed");
        }
    }
    else
    {
        healthy = false;
        reporter.Add(FindingSeverity::High, L"driver",
            L"Driver status response failed protocol validation");
    }

    return DrainFindings(device.get(), reporter) && healthy;
}

bool PollDriverSession(
    const ScanOptions& options,
    Reporter& reporter,
    bool runKernelScan)
{
    UniqueHandle device(CreateFileW(
        L"\\\\.\\OAC",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!device)
    {
        reporter.Add(FindingSeverity::Critical, L"driver/monitor",
            L"Lost the OAC kernel session: " + LastErrorMessage(GetLastError()));
        return false;
    }

    bool healthy = true;
    DWORD returned = 0;
    if (runKernelScan)
    {
        OAC_SCAN_REQUEST request{};
        request.Version = OAC_PROTOCOL_VERSION;
        request.Size = sizeof(request);
        if (options.verboseHandles) request.Flags |= OAC_SCAN_VERBOSE_HANDLES;
        if (options.privateKernelTraces) request.Flags |= OAC_SCAN_PRIVATE_KERNEL_TRACES;
        if (!DeviceIoControl(device.get(), IOCTL_OAC_RUN_KERNEL_SCAN,
                &request, sizeof(request), nullptr, 0, &returned, nullptr))
        {
            healthy = false;
            reporter.Add(FindingSeverity::Critical, L"driver/monitor",
                L"Continuous kernel scan failed: " +
                    LastErrorMessage(GetLastError()));
        }
    }

    OAC_STATUS_RESPONSE status{};
    returned = 0;
    if (!DeviceIoControl(device.get(), IOCTL_OAC_GET_STATUS,
            nullptr, 0, &status, sizeof(status), &returned, nullptr) ||
        returned < sizeof(status) || status.Version != OAC_PROTOCOL_VERSION ||
        status.Size != sizeof(status))
    {
        healthy = false;
        reporter.Add(FindingSeverity::Critical, L"driver/monitor",
            L"Continuous driver status failed protocol validation");
    }
    else
    {
        if (status.ClientProcessId != GetCurrentProcessId() ||
            status.ProtectedProcessId != options.targetProcessId)
        {
            healthy = false;
            reporter.Add(FindingSeverity::Critical, L"driver/monitor",
                L"OAC kernel protection identity changed during monitoring");
        }
        if (status.FindingsDropped != 0)
        {
            healthy = false;
            reporter.Add(FindingSeverity::Critical, L"driver/monitor",
                L"Kernel telemetry overflowed; dropped findings=" +
                    std::to_wstring(status.FindingsDropped));
        }
        if ((status.ConfigurationFlags &
             OAC_CONFIG_DRIVER_GATE) == 0)
        {
            healthy = false;
            reporter.Add(FindingSeverity::Critical, L"driver/monitor",
                L"Kernel driver-load gate became disarmed during monitoring");
        }
        if (!CheckDriverGate(status, L"driver/monitor", reporter))
            healthy = false;
    }

    if (!DrainFindings(device.get(), reporter)) healthy = false;
    return healthy;
}
