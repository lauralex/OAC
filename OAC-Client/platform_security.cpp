#include "scanner.hpp"

#include <Wbemidl.h>
#include <intrin.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <bit>
#include <optional>
#include <sstream>
#include <string_view>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Wbemuuid.lib")

namespace
{
using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

constexpr ULONG kSystemKernelDebuggerInformation = 35;
constexpr ULONG kSystemCodeIntegrityInformation = 103;
constexpr LONG kStatusSuccess = 0;

constexpr ULONG kCiEnabled = 0x00000001UL;
constexpr ULONG kCiTestSign = 0x00000002UL;
constexpr ULONG kCiUmciEnabled = 0x00000004UL;
constexpr ULONG kCiTestBuild = 0x00000020UL;
constexpr ULONG kCiPreproductionBuild = 0x00000040UL;
constexpr ULONG kCiDebugMode = 0x00000080UL;
constexpr ULONG kCiFlightBuild = 0x00000100UL;
constexpr ULONG kCiFlightingEnabled = 0x00000200UL;
constexpr ULONG kCiHvciEnabled = 0x00000400UL;
constexpr ULONG kCiHvciAudit = 0x00000800UL;
constexpr ULONG kCiHvciStrict = 0x00001000UL;
constexpr ULONG kCiIumEnabled = 0x00002000UL;

struct NativeCodeIntegrityInformation
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

struct NativeKernelDebuggerInformation
{
    BOOLEAN Enabled;
    BOOLEAN NotPresent;
};

template<typename T>
class ComPointer
{
public:
    ComPointer() = default;
    ~ComPointer() { reset(); }
    ComPointer(const ComPointer&) = delete;
    ComPointer& operator=(const ComPointer&) = delete;
    T* get() const noexcept { return value_; }
    T** put() noexcept
    {
        reset();
        return &value_;
    }
    T* operator->() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr; }
    void reset() noexcept
    {
        if (value_ != nullptr)
        {
            value_->Release();
            value_ = nullptr;
        }
    }

private:
    T* value_ = nullptr;
};

struct DeviceGuardState
{
    bool available = false;
    ULONG vbsStatus = 0;
    ULONG codeIntegrityPolicy = 0;
    ULONG userCodeIntegrityPolicy = 0;
    std::vector<ULONG> configuredServices;
    std::vector<ULONG> runningServices;
    std::vector<ULONG> availableProperties;
};

struct CpuidState
{
    bool hypervisorPresent = false;
    ULONG hypervisorMaximum = 0;
    std::array<char, 13> hypervisorVendor{};
    ULONG basicMaximum = 0;
    ULONG extendedMaximum = 0;
    bool rdtscpSupported = false;
    std::array<char, 13> cpuVendor{};
};

std::optional<DWORD> RegistryDword(
    HKEY root,
    const wchar_t* path,
    const wchar_t* name)
{
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    const LSTATUS status = RegGetValueW(root, path, name,
        RRF_RT_REG_DWORD, nullptr, &value, &bytes);
    if (status != ERROR_SUCCESS || bytes != sizeof(value)) return std::nullopt;
    return value;
}

std::wstring RegistryText(HKEY root, const wchar_t* path, const wchar_t* name)
{
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegGetValueW(root, path, name,
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            &type, nullptr, &bytes) != ERROR_SUCCESS ||
        bytes == 0 || bytes > size_t{64} * 1024)
        return {};
    std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1);
    if (RegGetValueW(root, path, name,
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            &type, value.data(), &bytes) != ERROR_SUCCESS)
        return {};
    value.back() = L'\0';
    return value.data();
}

bool ContainsVirtualFirmwareIndicator(std::wstring_view text)
{
    static constexpr std::wstring_view indicators[] =
    {
        L"vmware", L"virtualbox", L"qemu", L"kvm", L"xen", L"parallels",
        L"bochs", L"bhyve", L"hyper-v", L"virtual machine", L"hvm domu"
    };
    const std::wstring lower = oac::Lowercase(std::wstring(text));
    return std::ranges::any_of(indicators,
        [&lower](std::wstring_view indicator)
        {
            return lower.find(indicator) != std::wstring::npos;
        });
}

std::wstring AsciiToWide(const char* text, size_t maximum)
{
    std::wstring result;
    for (size_t index = 0; index < maximum && text[index] != '\0'; ++index)
    {
        const unsigned char character = static_cast<unsigned char>(text[index]);
        result += character >= 0x20 && character <= 0x7e
            ? static_cast<wchar_t>(character)
            : L'?';
    }
    return result;
}

bool PrintableVendor(const std::array<char, 13>& vendor)
{
    bool any = false;
    for (size_t index = 0; index < 12; ++index)
    {
        const unsigned char character = static_cast<unsigned char>(vendor[index]);
        if (character == 0) continue;
        if (character < 0x20 || character > 0x7e) return false;
        any = true;
    }
    return any;
}

CpuidState ReadCpuidState()
{
    CpuidState state;
    int registers[4]{};
    __cpuid(registers, 0);
    state.basicMaximum = static_cast<ULONG>(registers[0]);
    memcpy(state.cpuVendor.data() + 0, &registers[1], 4);
    memcpy(state.cpuVendor.data() + 4, &registers[3], 4);
    memcpy(state.cpuVendor.data() + 8, &registers[2], 4);
    __cpuid(registers, std::bit_cast<int>(0x80000000u));
    state.extendedMaximum = static_cast<ULONG>(registers[0]);
    if (state.extendedMaximum >= 0x80000001UL)
    {
        __cpuid(registers, std::bit_cast<int>(0x80000001u));
        state.rdtscpSupported =
            (static_cast<ULONG>(registers[3]) & (1UL << 27)) != 0;
    }
    __cpuid(registers, 1);
    state.hypervisorPresent =
        (static_cast<ULONG>(registers[2]) & (1UL << 31)) != 0;
    __cpuid(registers, 0x40000000);
    state.hypervisorMaximum = static_cast<ULONG>(registers[0]);
    memcpy(state.hypervisorVendor.data() + 0, &registers[1], 4);
    memcpy(state.hypervisorVendor.data() + 4, &registers[2], 4);
    memcpy(state.hypervisorVendor.data() + 8, &registers[3], 4);
    return state;
}

bool SameHypervisorState(const CpuidState& left, const CpuidState& right)
{
    return left.hypervisorPresent == right.hypervisorPresent &&
        left.hypervisorMaximum == right.hypervisorMaximum &&
        std::memcmp(left.hypervisorVendor.data(), right.hypervisorVendor.data(), 12) == 0;
}

std::vector<ULONG> VariantUnsignedValues(const VARIANT& value)
{
    std::vector<ULONG> result;
    if (value.vt == VT_UI4)
    {
        result.push_back(value.ulVal);
        return result;
    }
    if (value.vt == VT_I4)
    {
        result.push_back(static_cast<ULONG>(value.lVal));
        return result;
    }
    if ((value.vt & VT_ARRAY) == 0 || value.parray == nullptr) return result;

    LONG lower = 0;
    LONG upper = -1;
    if (SafeArrayGetDim(value.parray) != 1 ||
        FAILED(SafeArrayGetLBound(value.parray, 1, &lower)) ||
        FAILED(SafeArrayGetUBound(value.parray, 1, &upper)) || upper < lower ||
        static_cast<ULONGLONG>(static_cast<LONGLONG>(upper) - lower) > 1024)
        return result;
    for (LONG index = lower; index <= upper; ++index)
    {
        if ((value.vt & VT_TYPEMASK) == VT_UI4)
        {
            ULONG item = 0;
            if (SUCCEEDED(SafeArrayGetElement(value.parray, &index, &item)))
                result.push_back(item);
        }
        else if ((value.vt & VT_TYPEMASK) == VT_I4)
        {
            LONG item = 0;
            if (SUCCEEDED(SafeArrayGetElement(value.parray, &index, &item)))
                result.push_back(static_cast<ULONG>(item));
        }
    }
    return result;
}

std::vector<ULONG> WmiUnsignedValues(IWbemClassObject* object, const wchar_t* name)
{
    VARIANT value;
    VariantInit(&value);
    std::vector<ULONG> result;
    if (object != nullptr && SUCCEEDED(object->Get(name, 0, &value, nullptr, nullptr)))
        result = VariantUnsignedValues(value);
    VariantClear(&value);
    return result;
}

ULONG FirstOrZero(const std::vector<ULONG>& values)
{
    return values.empty() ? 0 : values.front();
}

DeviceGuardState QueryDeviceGuard(Reporter& reporter)
{
    DeviceGuardState state;
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool uninitialize = SUCCEEDED(initialized);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE)
    {
        reporter.Add(FindingSeverity::Low, L"platform/vbs",
            L"COM initialization failed; Win32_DeviceGuard is unavailable");
        return state;
    }

    const HRESULT security = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(security) && security != RPC_E_TOO_LATE)
        reporter.Add(FindingSeverity::Low, L"platform/vbs",
            L"COM security initialization failed; Device Guard telemetry may be incomplete");

    ComPointer<IWbemLocator> locator;
    ComPointer<IWbemServices> services;
    ComPointer<IEnumWbemClassObject> enumerator;
    HRESULT result = CoCreateInstance(CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator,
        reinterpret_cast<void**>(locator.put()));
    if (SUCCEEDED(result))
    {
        BSTR name = SysAllocString(L"ROOT\\Microsoft\\Windows\\DeviceGuard");
        if (name == nullptr) result = E_OUTOFMEMORY;
        else
        {
            result = locator->ConnectServer(name, nullptr, nullptr, nullptr, 0,
                nullptr, nullptr, services.put());
            SysFreeString(name);
        }
    }
    if (SUCCEEDED(result))
        result = CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (SUCCEEDED(result))
    {
        BSTR language = SysAllocString(L"WQL");
        BSTR query = SysAllocString(
            L"SELECT VirtualizationBasedSecurityStatus,SecurityServicesConfigured,"
            L"SecurityServicesRunning,AvailableSecurityProperties,"
            L"CodeIntegrityPolicyEnforcementStatus,"
            L"UsermodeCodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard");
        if (language == nullptr || query == nullptr) result = E_OUTOFMEMORY;
        else
            result = services->ExecQuery(language, query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, enumerator.put());
        if (language != nullptr) SysFreeString(language);
        if (query != nullptr) SysFreeString(query);
    }

    if (SUCCEEDED(result))
    {
        ComPointer<IWbemClassObject> object;
        ULONG returned = 0;
        result = enumerator->Next(5000, 1, object.put(), &returned);
        if (SUCCEEDED(result) && returned == 1)
        {
            state.available = true;
            state.vbsStatus = FirstOrZero(WmiUnsignedValues(
                object.get(), L"VirtualizationBasedSecurityStatus"));
            state.codeIntegrityPolicy = FirstOrZero(WmiUnsignedValues(
                object.get(), L"CodeIntegrityPolicyEnforcementStatus"));
            state.userCodeIntegrityPolicy = FirstOrZero(WmiUnsignedValues(
                object.get(), L"UsermodeCodeIntegrityPolicyEnforcementStatus"));
            state.configuredServices = WmiUnsignedValues(
                object.get(), L"SecurityServicesConfigured");
            state.runningServices = WmiUnsignedValues(
                object.get(), L"SecurityServicesRunning");
            state.availableProperties = WmiUnsignedValues(
                object.get(), L"AvailableSecurityProperties");
        }
    }
    if (!state.available)
        reporter.Add(FindingSeverity::Low, L"platform/vbs",
            L"Win32_DeviceGuard runtime state is unavailable");
    enumerator.reset();
    services.reset();
    locator.reset();
    if (uninitialize) CoUninitialize();
    return state;
}

std::wstring JoinValues(const std::vector<ULONG>& values)
{
    if (values.empty()) return L"none";
    std::wostringstream output;
    for (size_t index = 0; index < values.size(); ++index)
    {
        if (index != 0) output << L',';
        output << values[index];
    }
    return output.str();
}

void ScanCodeIntegrity(
    NtQuerySystemInformationFn query,
    const ScanOptions& scanOptions,
    Reporter& reporter,
    ULONG& codeIntegrityOptions)
{
    NativeCodeIntegrityInformation information{};
    information.Length = sizeof(information);
    ULONG returned = 0;
    const LONG status = query != nullptr
        ? query(kSystemCodeIntegrityInformation, &information,
            sizeof(information), &returned)
        : static_cast<LONG>(0xC0000002UL);
    if (status != kStatusSuccess || returned < sizeof(information) ||
        information.Length != sizeof(information))
    {
        reporter.Add(FindingSeverity::Medium, L"platform/code-integrity",
            L"SystemCodeIntegrityInformation is unavailable or malformed; status=" +
                std::to_wstring(static_cast<unsigned long>(status)));
        return;
    }
    codeIntegrityOptions = information.CodeIntegrityOptions;
    std::wostringstream message;
    message << L"Code Integrity options=0x" << std::hex << codeIntegrityOptions
            << L" kernel-enforced=" << ((codeIntegrityOptions & kCiEnabled) != 0)
            << L" UMCI=" << ((codeIntegrityOptions & kCiUmciEnabled) != 0)
            << L" HVCI=" << ((codeIntegrityOptions & kCiHvciEnabled) != 0)
            << L" HVCI-audit=" << ((codeIntegrityOptions & kCiHvciAudit) != 0)
            << L" HVCI-strict=" << ((codeIntegrityOptions & kCiHvciStrict) != 0)
            << L" IUM=" << ((codeIntegrityOptions & kCiIumEnabled) != 0);
    reporter.Add((codeIntegrityOptions & kCiEnabled) != 0
            ? FindingSeverity::Info : FindingSeverity::High,
        L"platform/code-integrity", message.str());
    if ((codeIntegrityOptions & kCiTestSign) != 0)
        reporter.Add(scanOptions.deploymentMode == DeploymentMode::Test
                ? FindingSeverity::Info
                : (scanOptions.deploymentMode == DeploymentMode::Production
                    ? FindingSeverity::Critical : FindingSeverity::Medium),
            L"platform/code-integrity",
            L"Code Integrity permits test-signed content; acceptable only on an isolated test machine");
    if ((codeIntegrityOptions & kCiDebugMode) != 0)
        reporter.Add(FindingSeverity::High, L"platform/code-integrity",
            L"Code Integrity debug mode is active and may permit unsigned kernel code");
    if ((codeIntegrityOptions & (kCiTestBuild | kCiPreproductionBuild | kCiFlightBuild |
                    kCiFlightingEnabled)) != 0)
        reporter.Add(FindingSeverity::Low, L"platform/code-integrity",
            L"Preproduction, test, or flight-signing Code Integrity policy is active");
}

void ScanSecureBoot(const ScanOptions& options, Reporter& reporter)
{
    (void)oac::EnablePrivilege(SE_SYSTEM_ENVIRONMENT_NAME);
    constexpr const wchar_t* globalNamespace =
        L"{8BE4DF61-93CA-11d2-AA0D-00E098032B8C}";
    BYTE secureBoot = 0;
    BYTE setupMode = 0;
    const DWORD secureBytes = GetFirmwareEnvironmentVariableW(
        L"SecureBoot", globalNamespace, &secureBoot, sizeof(secureBoot));
    const DWORD secureError = secureBytes == 0 ? GetLastError() : ERROR_SUCCESS;
    const DWORD setupBytes = GetFirmwareEnvironmentVariableW(
        L"SetupMode", globalNamespace, &setupMode, sizeof(setupMode));
    const auto registry = RegistryDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled");

    if (secureBytes == sizeof(secureBoot))
    {
        reporter.Add(secureBoot != 0 ? FindingSeverity::Info :
                (options.deploymentMode == DeploymentMode::Test
                    ? FindingSeverity::Low : FindingSeverity::Medium),
            L"platform/secure-boot",
            std::wstring(L"UEFI SecureBoot firmware variable=") +
                (secureBoot != 0 ? L"enabled" : L"disabled") +
                (setupBytes == sizeof(setupMode)
                    ? L"; SetupMode=" + std::to_wstring(setupMode)
                    : L"; SetupMode unavailable"));
        if (registry.has_value() && ((*registry != 0) != (secureBoot != 0)))
            reporter.Add(FindingSeverity::High, L"platform/secure-boot",
                L"Secure Boot firmware and registry runtime views disagree");
    }
    else if (secureError == ERROR_INVALID_FUNCTION)
        reporter.Add(FindingSeverity::Low, L"platform/secure-boot",
            L"Windows is running in legacy BIOS mode; UEFI Secure Boot is unavailable");
    else
        reporter.Add(FindingSeverity::Low, L"platform/secure-boot",
            L"Unable to read the UEFI SecureBoot variable; Win32 error=" +
                std::to_wstring(secureError));
}

void ScanKernelDebugger(NtQuerySystemInformationFn query, Reporter& reporter)
{
    NativeKernelDebuggerInformation information{};
    ULONG returned = 0;
    if (query == nullptr || query(kSystemKernelDebuggerInformation, &information,
            sizeof(information), &returned) != kStatusSuccess ||
        returned < sizeof(information))
    {
        reporter.Add(FindingSeverity::Low, L"platform/debugger",
            L"SystemKernelDebuggerInformation is unavailable");
        return;
    }
    if (information.Enabled && !information.NotPresent)
        reporter.Add(FindingSeverity::High, L"platform/debugger",
            L"The Windows kernel debugger is enabled and attached");
    else
        reporter.Add(FindingSeverity::Info, L"platform/debugger",
            L"No attached Windows kernel debugger was reported");
}

void ScanCpuidAndTiming(
    Reporter& reporter,
    ULONG codeIntegrityOptions,
    const DeviceGuardState& deviceGuard)
{
    const CpuidState baseline = ReadCpuidState();
    ULONG changes = 0;
    for (unsigned iteration = 0; iteration < 32; ++iteration)
        if (!SameHypervisorState(baseline, ReadCpuidState())) ++changes;

    const bool namespacePresent = baseline.hypervisorMaximum >= 0x40000000UL &&
        baseline.hypervisorMaximum <= 0x4000FFFFUL &&
        PrintableVendor(baseline.hypervisorVendor);
    if (changes != 0)
        reporter.Add(FindingSeverity::High, L"virtualization/cpuid",
            L"Hypervisor CPUID state changed across repeated serialized reads; changes=" +
                std::to_wstring(changes));
    if (!baseline.hypervisorPresent && namespacePresent)
        reporter.Add(FindingSeverity::High, L"virtualization/cpuid",
            L"A valid hypervisor CPUID namespace exists while the architectural hypervisor bit is clear");
    if (baseline.hypervisorPresent && !namespacePresent)
        reporter.Add(FindingSeverity::High, L"virtualization/cpuid",
            L"The architectural hypervisor bit is set but its CPUID namespace is malformed");

    const std::wstring manufacturer = RegistryText(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
    const std::wstring product = RegistryText(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    const bool virtualFirmware =
        ContainsVirtualFirmwareIndicator(manufacturer + L" " + product);
    if (virtualFirmware && !baseline.hypervisorPresent)
        reporter.Add(FindingSeverity::Medium, L"virtualization/consistency",
            L"Firmware identifies a virtual platform while CPUID hides the hypervisor-present bit");

    const bool vbsRunning = deviceGuard.available && deviceGuard.vbsStatus == 2;
    const bool hvciRunning = (codeIntegrityOptions & kCiHvciEnabled) != 0;
    if ((vbsRunning || hvciRunning) && !baseline.hypervisorPresent)
        reporter.Add(FindingSeverity::High, L"virtualization/consistency",
            L"Windows reports VBS/HVCI running while CPUID hides the required hypervisor");

    std::array<unsigned long long, 128> cycles{};
    ULONG backwards = 0;
    int registers[4]{};
    for (auto& sample : cycles)
    {
        unsigned int beforeAux = 0;
        unsigned int afterAux = 0;
        unsigned long long before = 0;
        unsigned long long after = 0;
        if (baseline.rdtscpSupported) before = __rdtscp(&beforeAux);
        else
        {
            _mm_lfence();
            before = __rdtsc();
        }
        __cpuidex(registers, 0, 0);
        if (baseline.rdtscpSupported) after = __rdtscp(&afterAux);
        else
        {
            after = __rdtsc();
            _mm_lfence();
        }
        if (after < before) ++backwards;
        sample = after - before;
    }
    std::ranges::sort(cycles);
    if (backwards != 0)
        reporter.Add(FindingSeverity::High, L"virtualization/timing",
            L"The timestamp counter moved backwards during serialized CPUID probes");

    std::wostringstream message;
    message << L"CPU vendor=" << AsciiToWide(baseline.cpuVendor.data(), 12)
            << L" hypervisor-bit=" << baseline.hypervisorPresent
            << L" hypervisor-vendor="
            << (namespacePresent
                ? AsciiToWide(baseline.hypervisorVendor.data(), 12)
                : L"none")
            << L" max-hypervisor-leaf=0x" << std::hex << baseline.hypervisorMaximum
            << L" CPUID latency cycles median/p95/max=" << std::dec
            << cycles[cycles.size() / 2] << L'/'
            << cycles[(cycles.size() * 95) / 100] << L'/' << cycles.back()
            << L"; timing is weak telemetry only";
    reporter.Add(baseline.hypervisorPresent ? FindingSeverity::Low : FindingSeverity::Info,
        L"virtualization/cpuid", message.str());

#ifdef PF_VIRT_FIRMWARE_ENABLED
    reporter.Add(FindingSeverity::Info, L"virtualization/platform",
        std::wstring(L"Firmware virtualization extensions enabled=") +
            (IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) ? L"true" : L"false"));
#endif
}
} // namespace

void ScanPlatformSecurity(const ScanOptions& options, Reporter& reporter)
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query = oac::ResolveFunction<NtQuerySystemInformationFn>(
        ntdll, "NtQuerySystemInformation");

    ULONG codeIntegrityOptions = 0;
    ScanCodeIntegrity(query, options, reporter, codeIntegrityOptions);
    ScanKernelDebugger(query, reporter);
    ScanSecureBoot(options, reporter);

    const DeviceGuardState deviceGuard = QueryDeviceGuard(reporter);
    if (deviceGuard.available)
    {
        reporter.Add(FindingSeverity::Info, L"platform/vbs",
            L"Device Guard runtime: VBS=" + std::to_wstring(deviceGuard.vbsStatus) +
                L" CI-policy=" + std::to_wstring(deviceGuard.codeIntegrityPolicy) +
                L" UMCI-policy=" + std::to_wstring(deviceGuard.userCodeIntegrityPolicy) +
                L" configured-services=" + JoinValues(deviceGuard.configuredServices) +
                L" running-services=" + JoinValues(deviceGuard.runningServices) +
                L" available-properties=" + JoinValues(deviceGuard.availableProperties));
    }

    const auto hvciConfigured = RegistryDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        L"Enabled");
    if (hvciConfigured.value_or(0) != 0 &&
        (codeIntegrityOptions & kCiHvciEnabled) == 0)
        reporter.Add(FindingSeverity::Medium, L"platform/vbs",
            L"HVCI is configured in policy but is not active in the runtime Code Integrity view");
    if (options.requireHvci && (codeIntegrityOptions & kCiHvciEnabled) == 0)
        reporter.Add(FindingSeverity::High, L"platform/vbs",
            L"HVCI is required by scan policy but is not active");

    const auto vulnerableBlocklist = RegistryDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        L"VulnerableDriverBlocklistEnable");
    if (vulnerableBlocklist.has_value() && *vulnerableBlocklist == 0)
        reporter.Add(FindingSeverity::Low,
            L"platform/code-integrity",
            L"The Microsoft vulnerable-driver blocklist is explicitly disabled; OAC's own "
            L"preflight/hash/family policy remains active independently");

    ScanCpuidAndTiming(reporter, codeIntegrityOptions, deviceGuard);
}
