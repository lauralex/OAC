#include "scanner.hpp"
#include "..\shared\oac_driver_policy.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <SetupAPI.h>
#include <bcrypt.h>
#include <cfgmgr32.h>
#include <intrin.h>
#include <winioctl.h>
#include <winternl.h>
#include <ntddstor.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <wintrust.h>
#include <winsvc.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Wintrust.lib")

namespace
{
using oac::UniqueHandle;
using oac::UniqueServiceHandle;

#include "driver_hash_policy.inc"

using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr ULONG kSystemProcessInformation = 5;
constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kDangerousProcessAccess = 0x0001UL | 0x0002UL | 0x0004UL |
    0x0008UL | 0x0010UL | 0x0020UL | 0x0040UL | 0x0080UL | 0x0100UL |
    0x0200UL | 0x0800UL | 0x2000UL | DELETE | WRITE_DAC | WRITE_OWNER;

struct NativeSystemProcessInformation
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
};

struct NativeHandleEntry
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct NativeHandleInformation
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    NativeHandleEntry Handles[1];
};

// std::set's implementation is non-throwing here; Clang-Tidy cannot prove the
// implicit special-member contract through the MSVC STL implementation.
struct ProcessView // NOLINT(bugprone-exception-escape)
{
    std::set<DWORD> processIds;
    bool available = false;
};

enum class ProcessLiveness : unsigned char
{
    Exited,
    Alive,
    Unknown
};

std::wstring CsvEscape(const std::wstring& value)
{
    std::wstring result = L"\"";
    for (const wchar_t character : value)
    {
        if (character == L'\"') result += L"\"\"";
        else if (character != L'\r' && character != L'\n') result += character;
    }
    result += L'\"';
    return result;
}

NtQuerySystemInformationFn NativeQuery()
{
    static const auto function = oac::ResolveFunction<NtQuerySystemInformationFn>(
        GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    return function;
}

std::vector<std::byte> QuerySystemInformation(ULONG informationClass)
{
    const auto query = NativeQuery();
    if (query == nullptr) return {};
    ULONG size = 1 << 20;
    for (unsigned attempt = 0; attempt < 10 && size <= 256UL * 1024UL * 1024UL; ++attempt)
    {
        std::vector<std::byte> buffer(size);
        ULONG needed = 0;
        const LONG status = query(informationClass, buffer.data(), size, &needed);
        if (status >= 0)
        {
            buffer.resize(needed != 0 && needed <= size ? needed : size);
            return buffer;
        }
        if (status != kStatusInfoLengthMismatch &&
            status != kStatusBufferTooSmall && status != kStatusBufferOverflow) return {};
        const ULONGLONG next = std::max<ULONGLONG>(
            static_cast<ULONGLONG>(size) * 2,
            static_cast<ULONGLONG>(needed) + 65536ULL);
        if (next > 256ULL * 1024ULL * 1024ULL) return {};
        size = static_cast<ULONG>(next);
    }
    return {};
}

ProcessView ToolhelpProcesses()
{
    ProcessView result;
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) return result;
    result.available = true;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot.get(), &entry))
    {
        do { result.processIds.insert(entry.th32ProcessID); }
        while (Process32NextW(snapshot.get(), &entry));
    }
    else
    {
        result.available = false;
    }
    return result;
}

ProcessView PsapiProcesses()
{
    ProcessView result;
    std::vector<DWORD> pids(4096);
    DWORD bytes = 0;
    for (;;)
    {
        if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &bytes))
            return result;
        if (bytes < pids.size() * sizeof(DWORD)) break;
        pids.resize(pids.size() * 2);
    }
    result.available = true;
    for (size_t i = 0; i < bytes / sizeof(DWORD); ++i)
        result.processIds.insert(pids[i]);
    return result;
}

ProcessView NativeProcesses()
{
    ProcessView result;
    auto buffer = QuerySystemInformation(kSystemProcessInformation);
    if (buffer.empty()) return result;
    result.available = true;
    size_t offset = 0;
    while (offset + sizeof(NativeSystemProcessInformation) <= buffer.size())
    {
        const auto* process = reinterpret_cast<const NativeSystemProcessInformation*>(buffer.data() + offset);
        result.processIds.insert(
            static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(process->UniqueProcessId)));
        if (process->NextEntryOffset == 0) break;
        if (process->NextEntryOffset < sizeof(NativeSystemProcessInformation) ||
            process->NextEntryOffset > buffer.size() - offset)
        {
            result.available = false;
            result.processIds.clear();
            break;
        }
        offset += process->NextEntryOffset;
    }
    return result;
}

ProcessLiveness QueryProcessLiveness(DWORD processId)
{
    if (processId == 0 || processId == 4) return ProcessLiveness::Alive;
    UniqueHandle process(OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE,
        processId));
    if (!process)
        return GetLastError() == ERROR_INVALID_PARAMETER
            ? ProcessLiveness::Exited
            : ProcessLiveness::Unknown;
    const DWORD wait = WaitForSingleObject(process.get(), 0);
    if (wait == WAIT_OBJECT_0) return ProcessLiveness::Exited;
    if (wait == WAIT_TIMEOUT) return ProcessLiveness::Alive;
    DWORD exitCode = 0;
    if (GetExitCodeProcess(process.get(), &exitCode))
        return exitCode == STILL_ACTIVE
            ? ProcessLiveness::Alive
            : ProcessLiveness::Exited;
    return ProcessLiveness::Unknown;
}

void ScanProcessCrossView(Reporter& reporter)
{
    const auto toolhelp = ToolhelpProcesses();
    const auto psapi = PsapiProcesses();
    const auto native = NativeProcesses();
    if (!toolhelp.available)
        reporter.Add(FindingSeverity::Medium, L"process/cross-view",
            L"Toolhelp process view is unavailable");
    if (!psapi.available)
        reporter.Add(FindingSeverity::Medium, L"process/cross-view",
            L"PSAPI process view is unavailable");
    if (!native.available)
        reporter.Add(FindingSeverity::Medium, L"process/cross-view",
            L"NtQuerySystemInformation process view is unavailable or malformed");
    const unsigned availableViews = static_cast<unsigned>(toolhelp.available) +
        static_cast<unsigned>(psapi.available) + static_cast<unsigned>(native.available);
    if (availableViews < 2)
    {
        reporter.Add(FindingSeverity::High, L"process/cross-view",
            L"Fewer than two independent process views are available; hidden-process comparison skipped");
        return;
    }

    std::set<DWORD> all = toolhelp.processIds;
    all.insert(psapi.processIds.begin(), psapi.processIds.end());
    all.insert(native.processIds.begin(), native.processIds.end());
    size_t mismatches = 0;
    for (const DWORD pid : all)
    {
        const bool a = toolhelp.processIds.contains(pid);
        const bool b = psapi.processIds.contains(pid);
        const bool c = native.processIds.contains(pid);
        const bool mismatch = (toolhelp.available && !a) ||
            (psapi.available && !b) || (native.available && !c);
        const ProcessLiveness liveness = mismatch
            ? QueryProcessLiveness(pid)
            : ProcessLiveness::Exited;
        if (mismatch && liveness != ProcessLiveness::Exited)
        {
            ++mismatches;
            std::wostringstream message;
            message << L"Process cross-view mismatch: Toolhelp=" << a
                    << L" PSAPI=" << b << L" NtQuerySystemInformation=" << c;
            reporter.Add(
                liveness == ProcessLiveness::Alive
                    ? FindingSeverity::High
                    : FindingSeverity::Medium,
                L"process/cross-view",
                message.str() + (liveness == ProcessLiveness::Unknown
                    ? L"; current liveness could not be confirmed"
                    : L""),
                pid);
        }
    }
    reporter.Add(FindingSeverity::Info, L"process/cross-view",
        L"Compared " + std::to_wstring(all.size()) + L" process IDs across three views; " +
            std::to_wstring(mismatches) + L" live mismatches");
}

void ReportOperatingSystem(Reporter& reporter)
{
    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    const auto getVersion = oac::ResolveFunction<RtlGetVersionFn>(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    if (getVersion != nullptr && getVersion(&version) >= 0)
    {
        std::wostringstream message;
        message << L"Windows " << version.dwMajorVersion << L'.' << version.dwMinorVersion
                << L" build " << version.dwBuildNumber << L"; architecture="
                << systemInfo.wProcessorArchitecture;
        reporter.Add(FindingSeverity::Info, L"compatibility", message.str());
    }
}

LONG VerifyFileTrust(const std::wstring& path);

std::wstring ProcessImagePath(DWORD processId)
{
    if (processId == 4) return L"System";
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, processId));
    if (!process) return {};
    std::vector<wchar_t> path(32768);
    DWORD characters = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(process.get(), 0, path.data(), &characters) ||
        characters == 0 || characters >= path.size())
        return {};
    return std::wstring(path.data(), characters);
}

bool IsTrustedWindowsImage(const std::wstring& path)
{
    if (path.empty() || path == L"System") return path == L"System";
    std::vector<wchar_t> windows(32768);
    if (GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size())) == 0)
        return false;
    std::wstring prefix = oac::Lowercase(windows.data());
    if (!prefix.ends_with(L'\\')) prefix += L'\\';
    const std::wstring lowerPath = oac::Lowercase(path);
    return lowerPath.starts_with(prefix) && VerifyFileTrust(path) == ERROR_SUCCESS;
}

void ScanHandles(const ScanOptions& options, Reporter& reporter)
{
    UniqueHandle target(options.targetProcessId != 0
        ? OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, options.targetProcessId)
        : nullptr);
    auto buffer = QuerySystemInformation(kSystemExtendedHandleInformation);
    if (buffer.size() < offsetof(NativeHandleInformation, Handles))
    {
        reporter.Add(FindingSeverity::Medium, L"handles", L"System handle enumeration failed");
        return;
    }

    const auto* information = reinterpret_cast<const NativeHandleInformation*>(buffer.data());
    const size_t maximum = (buffer.size() - offsetof(NativeHandleInformation, Handles)) /
                           sizeof(NativeHandleEntry);
    const size_t count = std::min(static_cast<size_t>(information->NumberOfHandles), maximum);
    PVOID targetObject = nullptr;
    if (target)
    {
        const ULONG_PTR currentPid = GetCurrentProcessId();
        const ULONG_PTR targetHandle = reinterpret_cast<ULONG_PTR>(target.get());
        for (size_t i = 0; i < count; ++i)
        {
            const auto& entry = information->Handles[i];
            if (entry.UniqueProcessId == currentPid && entry.HandleValue == targetHandle)
            {
                targetObject = entry.Object;
                break;
            }
        }
    }
    else if (options.targetProcessId != 0)
    {
        reporter.Add(FindingSeverity::Medium, L"handles/target",
            L"Target object identity could not be established; raw handle inventory remains available",
            options.targetProcessId);
    }

    const auto csvPath = options.outputDirectory / L"oac-open-handles.csv";
    std::ofstream csv(csvPath, std::ios::binary | std::ios::trunc);
    if (csv) csv << "owner_pid,handle,object,type_index,access,attributes\r\n";
    else
        reporter.Add(FindingSeverity::Medium, L"handles",
            L"Unable to create raw handle inventory: " + csvPath.wstring());

    size_t targetHandles = 0;
    struct HandleEvidence
    {
        size_t count = 0;
        ULONG combinedAccess = 0;
        ULONG_PTR firstHandle = 0;
    };
    std::map<DWORD, HandleEvidence> dangerousOwners;
    for (size_t i = 0; i < count; ++i)
    {
        const auto& entry = information->Handles[i];
        if (csv)
        {
            csv << entry.UniqueProcessId << ",0x" << std::hex << entry.HandleValue
                << ",0x" << reinterpret_cast<ULONG_PTR>(entry.Object)
                << std::dec << ',' << entry.ObjectTypeIndex << ",0x" << std::hex
                << entry.GrantedAccess << ",0x" << entry.HandleAttributes << std::dec << "\r\n";
        }

        if (targetObject != nullptr && entry.Object == targetObject)
        {
            ++targetHandles;
            const DWORD owner = static_cast<DWORD>(entry.UniqueProcessId);
            const ULONG dangerousAccess = entry.GrantedAccess & kDangerousProcessAccess;
            if (owner != GetCurrentProcessId() && owner != options.targetProcessId &&
                dangerousAccess != 0)
            {
                auto& evidence = dangerousOwners[owner];
                if (evidence.count == 0) evidence.firstHandle = entry.HandleValue;
                ++evidence.count;
                evidence.combinedAccess |= dangerousAccess;
            }
        }
    }

    for (const auto& [owner, evidence] : dangerousOwners)
    {
        const std::wstring path = ProcessImagePath(owner);
        const bool trustedWindows = IsTrustedWindowsImage(path);
        const bool mutationRights =
            (evidence.combinedAccess & ~static_cast<ULONG>(PROCESS_VM_READ)) != 0;
        std::wostringstream message;
        message << L"Process owns " << evidence.count
                << L" existing handles with protected-target "
                << (mutationRights ? L"mutation" : L"read")
                << L" rights; combined-rights=0x"
                << std::hex << evidence.combinedAccess << L" first-handle=0x"
                << evidence.firstHandle << L" image="
                << (path.empty() ? L"<unavailable>" : path);
        reporter.Add(trustedWindows ? FindingSeverity::Low :
                (mutationRights ? FindingSeverity::High : FindingSeverity::Medium),
            L"handles/target", message.str(), owner);
    }

    if (csv && !csv.good())
        reporter.Add(FindingSeverity::Medium, L"handles",
            L"Writing the raw handle inventory failed: " + csvPath.wstring());

    reporter.Add(FindingSeverity::Info, L"handles",
        L"Enumerated " + std::to_wstring(count) + L" open handles (" +
            std::to_wstring(targetHandles) + L" target handles)" +
            (csv ? L"; raw list: " + csvPath.wstring() : L"; raw list unavailable"));
}

std::wstring NormalizeDriverPath(std::wstring path)
{
    wchar_t windows[MAX_PATH]{};
    (void)GetWindowsDirectoryW(windows, static_cast<UINT>(std::size(windows)));
    if (path.starts_with(L"\\SystemRoot\\"))
        return std::wstring(windows) + path.substr(11);
    if (path.starts_with(L"\\??\\")) return path.substr(4);
    if (path.starts_with(L"\\Windows\\"))
    {
        wchar_t drive[4] = L"C:";
        if (windows[1] == L':') { drive[0] = windows[0]; drive[1] = L':'; }
        return std::wstring(drive) + path;
    }
    return path;
}

LONG VerifyEmbeddedTrust(const std::wstring& path)
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &fileInfo;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &action, &trust);
    return status;
}

LONG VerifyCatalogTrust(const std::wstring& path)
{
    using AcquireContext2Fn = BOOL(WINAPI*)(HCATADMIN*, const GUID*, LPCWSTR,
        PCCERT_STRONG_SIGN_PARA, DWORD);
    using CalculateHash2Fn = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);
    const HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
    const auto acquireContext2 = oac::ResolveFunction<AcquireContext2Fn>(
        wintrust, "CryptCATAdminAcquireContext2");
    const auto calculateHash2 = oac::ResolveFunction<CalculateHash2Fn>(
        wintrust, "CryptCATAdminCalcHashFromFileHandle2");
    HCATADMIN administrator = nullptr;
    bool modernCatalogApi = acquireContext2 != nullptr && calculateHash2 != nullptr;
    GUID driverAction = DRIVER_ACTION_VERIFY;
    BOOL acquired = modernCatalogApi
        ? acquireContext2(&administrator, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
        : CryptCATAdminAcquireContext(&administrator, &driverAction, 0);
    if (!acquired && modernCatalogApi)
    {
        modernCatalogApi = false;
        acquired = CryptCATAdminAcquireContext(&administrator, &driverAction, 0);
    }
    if (!acquired)
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);

    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file)
    {
        const DWORD error = GetLastError();
        CryptCATAdminReleaseContext(administrator, 0);
        return HRESULT_FROM_WIN32(error);
    }

    DWORD hashSize = 0;
    const auto calculateHash = [&](DWORD* size, BYTE* buffer) -> BOOL
    {
        return modernCatalogApi
            ? calculateHash2(administrator, file.get(), size, buffer, 0)
            : CryptCATAdminCalcHashFromFileHandle(file.get(), size, buffer, 0);
    };
    if (!calculateHash(&hashSize, nullptr) || hashSize == 0 || hashSize > 1024)
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);
    }
    std::vector<BYTE> hash(hashSize);
    if (!calculateHash(&hashSize, hash.data()))
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);
    }
    if (hashSize == 0 || hashSize > hash.size())
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);
    }
    hash.resize(hashSize);

    HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(
        administrator, hash.data(), hashSize, 0, nullptr);
    if (catalog == nullptr)
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return static_cast<LONG>(TRUST_E_NOSIGNATURE);
    }

    LONG status = static_cast<LONG>(TRUST_E_NOSIGNATURE);
    for (unsigned attempt = 0; catalog != nullptr && attempt < 128; ++attempt)
    {
        CATALOG_INFO catalogInfo{};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        if (CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0))
        {
            std::wostringstream tag;
            for (const BYTE byte : hash)
                tag << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0')
                    << static_cast<unsigned>(byte);
            const std::wstring memberTag = tag.str();

            WINTRUST_CATALOG_INFO member{};
            member.cbStruct = sizeof(member);
            member.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
            member.pcwszMemberTag = memberTag.c_str();
            member.pcwszMemberFilePath = path.c_str();
            member.hMemberFile = file.get();

            WINTRUST_DATA trust{};
            trust.cbStruct = sizeof(trust);
            trust.dwUIChoice = WTD_UI_NONE;
            trust.fdwRevocationChecks = WTD_REVOKE_NONE;
            trust.dwUnionChoice = WTD_CHOICE_CATALOG;
            trust.pCatalog = &member;
            trust.dwStateAction = WTD_STATEACTION_VERIFY;
            trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL |
                WTD_REVOCATION_CHECK_NONE;

            GUID action = DRIVER_ACTION_VERIFY;
            status = WinVerifyTrust(nullptr, &action, &trust);
            trust.dwStateAction = WTD_STATEACTION_CLOSE;
            (void)WinVerifyTrust(nullptr, &action, &trust);
            if (status == ERROR_SUCCESS) break;
        }

        HCATINFO previous = catalog;
        catalog = CryptCATAdminEnumCatalogFromHash(
            administrator,
            hash.data(),
            hashSize,
            0,
            &previous);
    }

    if (catalog != nullptr)
        CryptCATAdminReleaseCatalogContext(administrator, catalog, 0);
    CryptCATAdminReleaseContext(administrator, 0);
    return status;
}

LONG VerifyFileTrust(const std::wstring& path)
{
    const LONG embedded = VerifyEmbeddedTrust(path);
    return embedded == ERROR_SUCCESS ? embedded : VerifyCatalogTrust(path);
}

std::string CalculateAuthenticodeSha256(const std::wstring& path)
{
    using AcquireContext2Fn = BOOL(WINAPI*)(HCATADMIN*, const GUID*, LPCWSTR,
        PCCERT_STRONG_SIGN_PARA, DWORD);
    using CalculateHash2Fn = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);
    const HMODULE wintrust = GetModuleHandleW(L"wintrust.dll");
    const auto acquireContext2 = oac::ResolveFunction<AcquireContext2Fn>(
        wintrust, "CryptCATAdminAcquireContext2");
    const auto calculateHash2 = oac::ResolveFunction<CalculateHash2Fn>(
        wintrust, "CryptCATAdminCalcHashFromFileHandle2");
    if (acquireContext2 == nullptr || calculateHash2 == nullptr) return {};

    HCATADMIN administrator = nullptr;
    if (!acquireContext2(&administrator, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
        return {};

    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file)
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return {};
    }

    DWORD size = 0;
    if (!calculateHash2(administrator, file.get(), &size, nullptr, 0) || size != 32)
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return {};
    }
    std::array<BYTE, 32> hash{};
    if (!calculateHash2(administrator, file.get(), &size, hash.data(), 0) ||
        size != hash.size())
    {
        CryptCATAdminReleaseContext(administrator, 0);
        return {};
    }
    CryptCATAdminReleaseContext(administrator, 0);

    static constexpr char alphabet[] = "0123456789ABCDEF";
    std::string text(hash.size() * 2, '0');
    for (size_t index = 0; index < hash.size(); ++index)
    {
        text[index * 2] = alphabet[hash[index] >> 4];
        text[index * 2 + 1] = alphabet[hash[index] & 0x0f];
    }
    return text;
}

void ScanLoadedDrivers(
    const ScanOptions& options,
    Reporter& reporter,
    bool includeInventory)
{
    (void)oac::EnablePrivilege(SE_DEBUG_NAME);
    std::vector<LPVOID> drivers(2048);
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed))
    {
        reporter.Add(FindingSeverity::Medium, L"drivers", L"EnumDeviceDrivers failed");
        return;
    }
    if (needed > drivers.size() * sizeof(LPVOID))
    {
        drivers.resize((needed + sizeof(LPVOID) - 1) / sizeof(LPVOID));
        if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed))
        {
            reporter.Add(FindingSeverity::Medium, L"drivers",
                L"EnumDeviceDrivers retry failed");
            return;
        }
    }

    static constexpr std::wstring_view highBaseNames[] =
        { OAC_DRIVER_DENY_BASENAMES_W };
    static constexpr std::wstring_view reviewBaseNames[] =
        { OAC_DRIVER_REVIEW_BASENAMES_W };
    static std::set<std::wstring> evaluatedInstances;
    const size_t count = std::min(drivers.size(), static_cast<size_t>(needed / sizeof(LPVOID)));
    size_t checked = 0;
    size_t unnamed = 0;
    size_t newlyEvaluated = 0;
    std::vector<wchar_t> path(32768);
    for (size_t i = 0; i < count; ++i)
    {
        path[0] = L'\0';
        if (GetDeviceDriverFileNameW(drivers[i], path.data(), static_cast<DWORD>(path.size())) == 0)
        {
            ++unnamed;
            continue;
        }
        ++checked;
        const std::wstring normalized = NormalizeDriverPath(path.data());
        const std::wstring baseName = oac::Lowercase(
            std::filesystem::path(normalized).filename().wstring());
        std::wostringstream instance;
        instance << oac::Lowercase(normalized) << L'@' << std::hex
                 << reinterpret_cast<ULONG_PTR>(drivers[i]);
        const bool firstEvaluation = evaluatedInstances.insert(instance.str()).second;
        if (!includeInventory && !firstEvaluation) continue;
        ++newlyEvaluated;

        const bool suspicious = std::ranges::find(highBaseNames, baseName) !=
            std::end(highBaseNames);
        const bool review = std::ranges::find(reviewBaseNames, baseName) !=
            std::end(reviewBaseNames);
        const std::string authenticodeHash = CalculateAuthenticodeSha256(normalized);
        const bool exactDeny = !authenticodeHash.empty() && std::ranges::binary_search(
            kOacDeniedDriverAuthenticodeSha256, std::string_view(authenticodeHash));
        const LONG trust = VerifyFileTrust(normalized);
        const bool transientDumpDriver = baseName.starts_with(L"dump_") &&
            HRESULT_CODE(trust) == ERROR_FILE_NOT_FOUND;
        std::wostringstream message;
        message << (exactDeny ? L"Exact denied driver hash is loaded: " :
            (suspicious ? L"OAC deny-policy driver family is loaded: " :
                (review ? L"Loaded driver family requires version review: " : L"Loaded driver: ")))
                << normalized << L"; trust=0x" << std::hex << static_cast<ULONG>(trust)
                << L"; authenticode-sha256=";
        if (authenticodeHash.empty()) message << L"unavailable";
        else message << std::wstring(authenticodeHash.begin(), authenticodeHash.end());

        const FindingSeverity severity = exactDeny
            ? FindingSeverity::Critical
            : (suspicious
                ? (options.deploymentMode == DeploymentMode::Production
                    ? FindingSeverity::Critical : FindingSeverity::High)
                : (review ? FindingSeverity::Medium
                    : (trust == ERROR_SUCCESS || transientDumpDriver
                        ? FindingSeverity::Info : FindingSeverity::Medium)));
        if (includeInventory || severity != FindingSeverity::Info)
            reporter.Add(severity, L"drivers", message.str(), 0, 0,
                reinterpret_cast<unsigned long long>(drivers[i]));
    }
    if (includeInventory || newlyEvaluated != 0)
        reporter.Add(unnamed == 0 ? FindingSeverity::Info : FindingSeverity::Low,
            L"drivers",
            L"OAC driver policy " +
                std::wstring(kOacDriverPolicyVersion,
                    kOacDriverPolicyVersion + std::char_traits<char>::length(kOacDriverPolicyVersion)) +
                L" evaluated " + std::to_wstring(newlyEvaluated) + L" new of " +
                std::to_wstring(count) + L" loaded drivers; readable paths=" +
                std::to_wstring(checked) + L"; unnamed/unreadable paths=" +
                std::to_wstring(unnamed) + L"; exact SHA-256 denies=" +
                std::to_wstring(kOacDeniedDriverAuthenticodeSha256.size()));
}

std::wstring QueryServicePath(SC_HANDLE service)
{
    DWORD needed = 0;
    (void)QueryServiceConfigW(service, nullptr, 0, &needed);
    if (needed == 0) return {};
    std::vector<std::byte> buffer(needed);
    auto* configuration = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(service, configuration, needed, &needed) ||
        configuration->lpBinaryPathName == nullptr) return {};
    return configuration->lpBinaryPathName;
}

void ScanServices(const ScanOptions& options, Reporter& reporter)
{
    UniqueServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
    if (!manager)
    {
        reporter.Add(FindingSeverity::Medium, L"services", L"OpenSCManager failed");
        return;
    }

    const auto csvPath = options.outputDirectory / L"oac-services.csv";
    std::ofstream csv(csvPath, std::ios::binary | std::ios::trunc);
    if (csv) csv << "name,display_name,state,pid,path\r\n";
    else
        reporter.Add(FindingSeverity::Medium, L"services",
            L"Unable to create service inventory: " + csvPath.wstring());
    static constexpr std::wstring_view highServiceNames[] =
    {
        L"dbk", L"dbk64", L"cheatengine", L"kprocesshacker", L"winio",
        L"winio64", L"gdrv", L"gdrv2", L"iqvw64e", L"mhyprot",
        L"mhyprot2", L"capcom", L"rtcore64"
    };
    static constexpr std::wstring_view highPathNames[] =
    {
        L"\\dbk64.sys", L"\\capcom.sys", L"\\gdrv.sys",
        L"\\iqvw64e.sys", L"\\winio64.sys", L"\\rtcore64.sys",
        L"\\kprocesshacker.sys", L"\\mhyprot"
    };

    std::vector<std::byte> buffer(size_t{64} * 1024);
    DWORD resume = 0;
    size_t total = 0;
    bool completed = false;
    for (unsigned page = 0; page < 128; ++page)
    {
        DWORD needed = 0;
        DWORD count = 0;
        const DWORD previousResume = resume;
        const BOOL success = EnumServicesStatusExW(
            manager.get(),
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            reinterpret_cast<LPBYTE>(buffer.data()),
            static_cast<DWORD>(buffer.size()),
            &needed,
            &count,
            &resume,
            nullptr);
        const DWORD error = success ? ERROR_SUCCESS : GetLastError();
        if (!success && error != ERROR_MORE_DATA)
        {
            reporter.Add(FindingSeverity::Medium, L"services",
                L"Service enumeration failed with Win32 error " +
                    std::to_wstring(error));
            break;
        }

        if (count == 0 && !success && needed > buffer.size())
        {
            if (needed > size_t{16} * 1024 * 1024)
            {
                reporter.Add(FindingSeverity::Medium, L"services",
                    L"Service enumeration requested an implausibly large buffer");
                break;
            }
            buffer.resize(static_cast<size_t>(needed) + 65536);
            resume = previousResume;
            continue;
        }

        const auto* services =
            reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < count; ++i)
        {
            if (services[i].lpServiceName == nullptr ||
                services[i].lpDisplayName == nullptr) continue;
            ++total;
            UniqueServiceHandle service(OpenServiceW(
                manager.get(),
                services[i].lpServiceName,
                SERVICE_QUERY_CONFIG));
            const std::wstring path = service ? QueryServicePath(service.get()) : L"";
            std::wstring combined = services[i].lpServiceName;
            combined += L' ';
            combined += path;
            const std::wstring lowerName = oac::Lowercase(services[i].lpServiceName);
            const std::wstring lowerPath = oac::Lowercase(path);
            const bool suspicious =
                std::ranges::find(highServiceNames, lowerName) !=
                    std::end(highServiceNames) ||
                std::ranges::any_of(highPathNames,
                    [&lowerPath](std::wstring_view indicator)
                    {
                        return lowerPath.find(indicator) != std::wstring::npos;
                    });
            const bool virtualBox = lowerName == L"vboxdrv" ||
                lowerPath.find(L"\\vboxdrv.sys") != std::wstring::npos;
            if (csv)
            {
                const std::wstring line = CsvEscape(services[i].lpServiceName) + L"," +
                    CsvEscape(services[i].lpDisplayName) + L"," +
                    std::to_wstring(services[i].ServiceStatusProcess.dwCurrentState) + L"," +
                    std::to_wstring(services[i].ServiceStatusProcess.dwProcessId) + L"," +
                    CsvEscape(path) + L"\r\n";
                csv << oac::Utf8(line);
            }
            if (suspicious)
            {
                reporter.Add(FindingSeverity::High, L"services",
                    L"Suspicious service/driver IOC: " + combined,
                    services[i].ServiceStatusProcess.dwProcessId);
            }
            else if (virtualBox)
                reporter.Add(FindingSeverity::Low, L"services/virtualization",
                    L"VirtualBox driver service is installed; version and signature determine risk",
                    services[i].ServiceStatusProcess.dwProcessId);
        }

        if (success)
        {
            completed = true;
            break;
        }
    }

    if (!completed)
        reporter.Add(FindingSeverity::Medium, L"services",
            L"Service inventory is incomplete");
    if (csv && !csv.good())
        reporter.Add(FindingSeverity::Medium, L"services",
            L"Writing the service inventory failed: " + csvPath.wstring());
    reporter.Add(FindingSeverity::Info, L"services",
        L"Checked " + std::to_wstring(total) + L" services and drivers" +
            (csv ? L"; inventory: " + csvPath.wstring() : L"; inventory unavailable"));
}

std::wstring DeviceProperty(HDEVINFO set, SP_DEVINFO_DATA& device, DWORD property)
{
    DWORD type = 0;
    DWORD needed = 0;
    (void)SetupDiGetDeviceRegistryPropertyW(set, &device, property, &type, nullptr, 0, &needed);
    if (needed == 0 || needed > 1024 * 1024 ||
        (needed % sizeof(wchar_t)) != 0 ||
        (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)) return {};
    std::vector<wchar_t> buffer(needed / sizeof(wchar_t) + 1);
    const DWORD capacity = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, property, &type,
            reinterpret_cast<PBYTE>(buffer.data()), capacity, &needed) ||
        needed > capacity || (needed % sizeof(wchar_t)) != 0) return {};
    return std::wstring(buffer.data(), wcsnlen_s(
        buffer.data(), needed / sizeof(wchar_t)));
}

void ScanDevicesAndDisks(Reporter& reporter)
{
    const DWORD required = GetLogicalDriveStringsW(0, nullptr);
    std::vector<wchar_t> drives(required == 0 ? 1 : required);
    const DWORD length = required == 0 ? 0 : GetLogicalDriveStringsW(
        static_cast<DWORD>(drives.size()), drives.data());
    if (length == 0 || length >= drives.size())
    {
        reporter.Add(FindingSeverity::Low, L"devices/disk",
            L"Logical-drive enumeration is unavailable or incomplete");
    }
    std::vector<wchar_t> mapping(32768);
    for (const wchar_t* drive = drives.data();
         length != 0 && drive < drives.data() + length && *drive != L'\0';
         drive += wcslen(drive) + 1)
    {
        wchar_t volumeName[MAX_PATH]{};
        DWORD serial = 0;
        wchar_t fileSystem[64]{};
        (void)GetVolumeInformationW(drive, volumeName, static_cast<DWORD>(std::size(volumeName)),
            &serial, nullptr, nullptr, fileSystem, static_cast<DWORD>(std::size(fileSystem)));
        mapping[0] = L'\0';
        wchar_t deviceName[3] = {drive[0], L':', L'\0'};
        (void)QueryDosDeviceW(deviceName, mapping.data(), static_cast<DWORD>(mapping.size()));
        std::wostringstream message;
        message << L"Disk " << drive << L" volume=" << volumeName << L" fs=" << fileSystem
                << L" volume-serial-present=" << (serial != 0) << L" device=" << mapping.data();
        reporter.Add(FindingSeverity::Info, L"devices/disk", message.str());
    }

    for (unsigned index = 0; index < 32; ++index)
    {
        const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(index);
        UniqueHandle disk(CreateFileW(path.c_str(), 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!disk) continue;
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        std::array<std::byte, 4096> output{};
        DWORD returned = 0;
        if (DeviceIoControl(disk.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                output.data(), static_cast<DWORD>(output.size()), &returned, nullptr) &&
            returned >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(output.data());
            auto field = [&](DWORD offset) -> std::wstring
            {
                if (offset == 0 || offset >= returned) return {};
                const char* value = reinterpret_cast<const char*>(output.data()) + offset;
                const size_t maximum = returned - offset;
                const size_t actual = strnlen_s(value, maximum);
                std::wstring result(actual, L'\0');
                for (size_t i = 0; i < actual; ++i) result[i] = static_cast<unsigned char>(value[i]);
                return result;
            };
            reporter.Add(FindingSeverity::Info, L"devices/disk",
                path + L" vendor=" + field(descriptor->VendorIdOffset) +
                    L" product=" + field(descriptor->ProductIdOffset) +
                    L" serial-present=" +
                    (field(descriptor->SerialNumberOffset).empty() ? L"false" : L"true"));
        }
    }

    HDEVINFO set = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (set != INVALID_HANDLE_VALUE)
    {
        size_t count = 0;
        for (DWORD index = 0;; ++index)
        {
            SP_DEVINFO_DATA device{};
            device.cbSize = sizeof(device);
            if (!SetupDiEnumDeviceInfo(set, index, &device))
            {
                if (GetLastError() != ERROR_NO_MORE_ITEMS)
                    reporter.Add(FindingSeverity::Medium, L"devices",
                        L"PnP device enumeration ended on an unexpected error");
                break;
            }
            ++count;
            std::wstring name = DeviceProperty(set, device, SPDRP_FRIENDLYNAME);
            if (name.empty()) name = DeviceProperty(set, device, SPDRP_DEVICEDESC);
            const std::wstring service = DeviceProperty(set, device, SPDRP_SERVICE);
            static constexpr std::wstring_view highServices[] =
            {
                L"winio", L"winio64", L"dbk", L"dbk64", L"capcom",
                L"iqvw64e", L"gdrv", L"gdrv2", L"rtcore64",
                L"mhyprot", L"mhyprot2", L"mhyprot3"
            };
            const std::wstring lowerService = oac::Lowercase(service);
            const std::wstring lowerName = oac::Lowercase(name);
            const bool highConfidence =
                std::ranges::find(highServices, lowerService) !=
                    std::end(highServices) ||
                lowerName.find(L"cheat engine") != std::wstring::npos;
            if (highConfidence)
            {
                std::wstring message = L"Suspicious device: ";
                message += name;
                message += L" service=";
                message += service;
                reporter.Add(FindingSeverity::High, L"devices", message);
            }
            else if (lowerService == L"vboxdrv")
            {
                reporter.Add(FindingSeverity::Low, L"devices/virtualization",
                    L"VirtualBox device is present; version and signature determine risk");
            }
        }
        SetupDiDestroyDeviceInfoList(set);
        reporter.Add(FindingSeverity::Info, L"devices",
            L"Enumerated " + std::to_wstring(count) + L" present PnP devices");
    }

    std::vector<wchar_t> names(size_t{64} * 1024);
    DWORD characters = 0;
    for (unsigned attempt = 0; attempt < 5; ++attempt)
    {
        characters = QueryDosDeviceW(
            nullptr,
            names.data(),
            static_cast<DWORD>(names.size()));
        if (characters != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) break;
        names.resize(names.size() * 2);
    }
    size_t dosDevices = 0;
    if (characters != 0)
    {
        for (const wchar_t* name = names.data(); *name != L'\0'; name += wcslen(name) + 1)
        {
            ++dosDevices;
            static constexpr std::wstring_view highNames[] =
            {
                L"winio", L"winio64", L"dbk", L"dbk64", L"dbkkernel",
                L"nal", L"gdrv", L"gdrv2", L"rtcore64", L"global\\rtcore64"
            };
            const std::wstring lowerName = oac::Lowercase(name);
            if (std::ranges::find(highNames, lowerName) != std::end(highNames))
                reporter.Add(FindingSeverity::High, L"devices", L"Suspicious DOS device: " +
                    std::wstring(name));
            else if (lowerName == L"vboxdrv")
                reporter.Add(FindingSeverity::Low, L"devices/virtualization",
                    L"VirtualBox DOS device is present; version and signature determine risk");
        }
    }
    reporter.Add(FindingSeverity::Info, L"devices",
        L"Enumerated " + std::to_wstring(dosDevices) + L" DOS device names");
}

void ScanTdlArtifacts(Reporter& reporter)
{
    wchar_t windows[MAX_PATH]{};
    const UINT windowsLength = GetWindowsDirectoryW(
        windows, static_cast<UINT>(std::size(windows)));
    if (windowsLength == 0 || windowsLength >= std::size(windows))
    {
        reporter.Add(FindingSeverity::Low, L"drivers/tdl",
            L"Windows directory is unavailable; TDL artifact path was not checked");
        return;
    }
    const std::filesystem::path backup = std::filesystem::path(windows) /
        L"System32" / L"drivers" / L"VBoxDrv.backup";
    std::error_code backupError;
    const bool backupExists = std::filesystem::exists(backup, backupError);
    if (backupError)
        reporter.Add(FindingSeverity::Low, L"drivers/tdl",
            L"Unable to query VBoxDrv.backup; error=" +
                std::to_wstring(backupError.value()));
    UniqueHandle device(CreateFileW(L"\\\\.\\VBoxDrv", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (backupExists)
        reporter.Add(FindingSeverity::High, L"drivers/tdl",
            L"Turla Driver Loader artifact exists: " + backup.wstring());
    if (device)
        reporter.Add(backupExists ? FindingSeverity::High : FindingSeverity::Low,
            L"drivers/tdl",
            L"VBoxDrv device is reachable; check its version against the vulnerable-driver blocklist");
    if (!backupExists && !device)
        reporter.Add(FindingSeverity::Info, L"drivers/tdl",
            L"No VBoxDrv.backup or reachable VBoxDrv device was found");
}
} // namespace

std::wstring QueryProcessImagePath(DWORD processId)
{
    return ProcessImagePath(processId);
}

bool IsTrustedWindowsImagePath(const std::wstring& path)
{
    return IsTrustedWindowsImage(path);
}

void RunSystemScan(const ScanOptions& options, Reporter& reporter)
{
    (void)oac::EnablePrivilege(SE_DEBUG_NAME);
    ReportOperatingSystem(reporter);
    ScanProcessCrossView(reporter);
    ScanHandles(options, reporter);
    ScanLoadedDrivers(options, reporter, true);
    ScanServices(options, reporter);
    ScanDevicesAndDisks(reporter);
    ScanHardwareIdentity(reporter);
    ScanPlatformSecurity(options, reporter);
    ScanTdlArtifacts(reporter);
}

void ScanLoadedDriverPolicy(const ScanOptions& options, Reporter& reporter)
{
    ScanLoadedDrivers(options, reporter, false);
}

void ScanTargetHandlePolicy(const ScanOptions& options, Reporter& reporter)
{
    (void)oac::EnablePrivilege(SE_DEBUG_NAME);
    ScanHandles(options, reporter);
}
