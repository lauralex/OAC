#include "scanner.hpp"
#include "..\shared\oac_thread_suspension.hpp"

#include <TlHelp32.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <intrin.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "User32.lib")

namespace
{
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);

constexpr ULONG kProcessDebugPort = 7;
constexpr ULONG kProcessDebugObjectHandle = 30;
constexpr ULONG kProcessDebugFlags = 31;
constexpr ULONG kProcessInstrumentationCallback = 40;
constexpr ULONG kThreadQuerySetWin32StartAddress = 9;
constexpr ULONG kThreadHideFromDebugger = 17;
constexpr size_t kMaximumMemoryScan = 256ULL * 1024ULL * 1024ULL;
constexpr DWORD64 kDr6StatusMask = 0xE00FULL;

struct InstrumentationCallbackInformation
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};

struct ModuleRecord
{
    uintptr_t base = 0;
    size_t size = 0;
    std::wstring path;
    bool toolhelp = false;
    bool psapi = false;
    bool memoryImage = false;
};

class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueHandle() { if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    HANDLE get() const noexcept { return handle_; }
    explicit operator bool() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE handle_;
};

std::wstring Lower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t character) { return static_cast<wchar_t>(std::towlower(character)); });
    return value;
}

std::wstring BaseName(const std::wstring& path)
{
    const size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

bool IsExecutable(DWORD protection)
{
    if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0) return false;
    switch (protection & 0xFF)
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

bool IsWritableExecutable(DWORD protection)
{
    const DWORD base = protection & 0xFF;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

template<typename T>
bool ReadRemote(HANDLE process, uintptr_t address, T& value)
{
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
        &value, sizeof(value), &read) && read == sizeof(value);
}

bool ReadRemoteBytes(HANDLE process, uintptr_t address, void* buffer, size_t size)
{
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
        buffer, size, &read) && read == size;
}

std::string ReadRemoteAscii(HANDLE process, uintptr_t address, size_t maximum = 512)
{
    std::string result;
    result.reserve(maximum);
    for (size_t offset = 0; offset < maximum; ++offset)
    {
        char character = '\0';
        if (!ReadRemote(process, address + offset, character) || character == '\0') break;
        if (static_cast<unsigned char>(character) < 0x20 ||
            static_cast<unsigned char>(character) > 0x7E) break;
        result.push_back(character);
    }
    return result;
}

std::wstring Widen(std::string_view value)
{
    std::wstring result;
    result.reserve(value.size());
    for (const unsigned char character : value) result.push_back(character);
    return result;
}

bool AddressInModules(uintptr_t address, const std::vector<ModuleRecord>& modules,
    const ModuleRecord** containing = nullptr)
{
    for (const auto& module : modules)
    {
        if (address >= module.base && address - module.base < module.size)
        {
            if (containing != nullptr) *containing = &module;
            return true;
        }
    }
    return false;
}

bool RvaRangeValid(const ModuleRecord& module, ULONGLONG rva, size_t size)
{
    return rva <= module.size && size <= module.size - static_cast<size_t>(rva);
}

bool IsSupportedTargetArchitecture(HANDLE process, DWORD processId, Reporter& reporter)
{
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto isWow64Process2 = ResolveFunction<IsWow64Process2Fn>(
        GetModuleHandleW(L"kernel32.dll"),
        "IsWow64Process2");
    if (isWow64Process2 != nullptr)
    {
        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!isWow64Process2(process, &processMachine, &nativeMachine))
        {
            reporter.Add(FindingSeverity::Medium, L"compatibility",
                L"Unable to determine target process architecture", processId);
            return false;
        }
        if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN ||
            nativeMachine != IMAGE_FILE_MACHINE_AMD64)
        {
            reporter.Add(FindingSeverity::Critical, L"compatibility",
                L"This build safely supports only native x64 target processes on x64 Windows",
                processId);
            return false;
        }
        return true;
    }

    BOOL wow64 = FALSE;
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    if (!IsWow64Process(process, &wow64) || wow64 ||
        systemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
    {
        reporter.Add(FindingSeverity::Critical, L"compatibility",
            L"This build safely supports only native x64 target processes on x64 Windows",
            processId);
        return false;
    }
    return true;
}

std::vector<ModuleRecord> EnumerateModules(HANDLE process, DWORD processId, Reporter& reporter)
{
    std::map<uintptr_t, ModuleRecord> records;
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId));
    if (snapshot)
    {
        MODULEENTRY32W module{};
        module.dwSize = sizeof(module);
        if (Module32FirstW(snapshot.get(), &module))
        {
            do
            {
                auto& record = records[reinterpret_cast<uintptr_t>(module.modBaseAddr)];
                record.base = reinterpret_cast<uintptr_t>(module.modBaseAddr);
                record.size = module.modBaseSize;
                record.path = module.szExePath;
                record.toolhelp = true;
            } while (Module32NextW(snapshot.get(), &module));
        }
    }

    std::vector<HMODULE> psapiModules(1024);
    std::vector<wchar_t> modulePath(32768);
    DWORD needed = 0;
    for (;;)
    {
        if (!EnumProcessModulesEx(process, psapiModules.data(),
                static_cast<DWORD>(psapiModules.size() * sizeof(HMODULE)), &needed,
                LIST_MODULES_ALL)) break;
        if (needed <= psapiModules.size() * sizeof(HMODULE))
        {
            const size_t count = needed / sizeof(HMODULE);
            for (size_t i = 0; i < count; ++i)
            {
                MODULEINFO information{};
                modulePath[0] = L'\0';
                if (!GetModuleInformation(process, psapiModules[i], &information, sizeof(information)))
                    continue;
                (void)GetModuleFileNameExW(process, psapiModules[i], modulePath.data(),
                    static_cast<DWORD>(modulePath.size()));
                auto& record = records[reinterpret_cast<uintptr_t>(information.lpBaseOfDll)];
                record.base = reinterpret_cast<uintptr_t>(information.lpBaseOfDll);
                record.size = information.SizeOfImage;
                if (record.path.empty()) record.path = modulePath.data();
                record.psapi = true;
            }
            break;
        }
        psapiModules.resize((needed + sizeof(HMODULE) - 1) / sizeof(HMODULE));
    }

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    uintptr_t address = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);
    unsigned queryFailures = 0;
    while (address < maximum)
    {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &memory, sizeof(memory)) == 0)
        {
            const uintptr_t next = address + systemInfo.dwPageSize;
            if (next <= address || ++queryFailures > 1024) break;
            address = next;
            continue;
        }
        queryFailures = 0;
        const uintptr_t next = reinterpret_cast<uintptr_t>(memory.BaseAddress) + memory.RegionSize;
        if (memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE)
        {
            const uintptr_t allocationBase = reinterpret_cast<uintptr_t>(memory.AllocationBase);
            auto& record = records[allocationBase];
            record.base = allocationBase;
            record.memoryImage = true;
            record.size = std::max(record.size,
                static_cast<size_t>(next > allocationBase ? next - allocationBase : memory.RegionSize));
            if (record.path.empty())
            {
                std::vector<wchar_t> path(32768);
                if (GetMappedFileNameW(process, memory.AllocationBase, path.data(),
                        static_cast<DWORD>(path.size())) != 0) record.path = path.data();
            }
        }
        if (next <= address) break;
        address = next;
    }

    std::vector<ModuleRecord> result;
    result.reserve(records.size());
    static const std::vector<std::wstring_view> suspiciousDlls =
    {
        L"cheatengine", L"speedhack", L"dbk64", L"injector"
    };
    static const std::vector<std::wstring_view> overlayDlls =
    {
        L"minhook", L"discordhook", L"gameoverlayrenderer", L"reshade",
        L"rtsshook", L"easyhook", L"detours"
    };
    for (auto& [base, record] : records)
    {
        UNREFERENCED_PARAMETER(base);
        if (record.toolhelp != record.psapi ||
            ((record.toolhelp || record.psapi) && !record.memoryImage))
        {
            std::wostringstream message;
            message << L"Module cross-view mismatch for "
                    << (record.path.empty() ? L"<unnamed>" : record.path)
                    << L": Toolhelp=" << record.toolhelp << L" PSAPI=" << record.psapi
                    << L" memory-image=" << record.memoryImage;
            reporter.Add(FindingSeverity::High, L"process/modules", message.str(), processId,
                0, record.base);
        }
        else if (record.memoryImage && !record.toolhelp && !record.psapi)
        {
            reporter.Add(FindingSeverity::Low, L"process/modules",
                L"Mapped image is not registered as a loader module: " +
                    (record.path.empty() ? std::wstring(L"<unnamed>") : record.path),
                processId, 0, record.base);
        }
        const std::wstring lowerName = Lower(BaseName(record.path));
        for (const auto indicator : suspiciousDlls)
        {
            if (lowerName.find(indicator) != std::wstring::npos)
            {
                reporter.Add(FindingSeverity::High, L"process/modules",
                    L"Suspicious injected/overlay DLL IOC: " + record.path,
                    processId, 0, record.base);
                break;
            }
        }
        for (const auto indicator : overlayDlls)
        {
            if (lowerName.find(indicator) != std::wstring::npos)
            {
                reporter.Add(FindingSeverity::Medium, L"process/modules",
                    L"Overlay/hooking module requiring allowlist review: " + record.path,
                    processId, 0, record.base);
                break;
            }
        }
        result.push_back(std::move(record));
    }
    std::sort(result.begin(), result.end(),
        [](const ModuleRecord& left, const ModuleRecord& right) { return left.base < right.base; });
    reporter.Add(FindingSeverity::Info, L"process/modules",
        L"Cross-checked " + std::to_wstring(result.size()) + L" modules across three views",
        processId);
    return result;
}

bool LooksLikePe(const std::vector<std::byte>& buffer, size_t offset)
{
    if (offset + sizeof(IMAGE_DOS_HEADER) > buffer.size()) return false;
    IMAGE_DOS_HEADER dos{};
    memcpy(&dos, buffer.data() + offset, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 || dos.e_lfanew > 0x1000)
        return false;
    const size_t signature = offset + static_cast<size_t>(dos.e_lfanew);
    DWORD value = 0;
    if (signature + sizeof(value) > buffer.size()) return false;
    memcpy(&value, buffer.data() + signature, sizeof(value));
    return value == IMAGE_NT_SIGNATURE;
}

std::string PrintableContext(const std::vector<std::byte>& data, size_t match)
{
    size_t begin = match;
    while (begin > 0 && match - begin < 80)
    {
        const unsigned char character = static_cast<unsigned char>(data[begin - 1]);
        if (character < 0x20 || character > 0x7E) break;
        --begin;
    }
    size_t end = match;
    while (end < data.size() && end - match < 160)
    {
        const unsigned char character = static_cast<unsigned char>(data[end]);
        if (character < 0x20 || character > 0x7E) break;
        ++end;
    }
    return std::string(reinterpret_cast<const char*>(data.data() + begin), end - begin);
}

void ScanUnbackedMemory(HANDLE process, DWORD processId,
    const ScanOptions& options, Reporter& reporter)
{
    const auto dumpPath = options.outputDirectory /
        (L"oac-suspect-strings-" + std::to_wstring(processId) + L".txt");
    std::ofstream dump(dumpPath, std::ios::binary | std::ios::trunc);
    if (!dump)
    {
        reporter.Add(FindingSeverity::Medium, L"process/memory",
            L"Unable to create suspect-string dump: " + dumpPath.wstring(), processId);
    }
    static const std::array<std::string_view, 10> strings =
    {
        "cheatengine", "silentaim", "manualmap", "kdmapper", "aimbot",
        "imgui_impldx", "minhook", "mouse_event", "ntsetinformationthread",
        "dbguiremotebreakin"
    };

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    uintptr_t address = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);
    size_t attempted = 0;
    size_t scanned = 0;
    size_t suspiciousRegions = 0;
    std::set<uintptr_t> privateAllocations;
    std::set<uintptr_t> mappedAllocations;
    std::set<uintptr_t> writableAllocations;
    unsigned queryFailures = 0;
    while (address < maximum)
    {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &memory, sizeof(memory)) == 0)
        {
            const uintptr_t next = address + systemInfo.dwPageSize;
            if (next <= address || ++queryFailures > 1024) break;
            address = next;
            continue;
        }
        queryFailures = 0;
        const uintptr_t base = reinterpret_cast<uintptr_t>(memory.BaseAddress);
        const uintptr_t next = base + memory.RegionSize;
        if (memory.State == MEM_COMMIT && IsExecutable(memory.Protect))
        {
            const bool unbacked = memory.Type != MEM_IMAGE;
            const uintptr_t allocationBase =
                reinterpret_cast<uintptr_t>(memory.AllocationBase);
            if (IsWritableExecutable(memory.Protect) &&
                writableAllocations.insert(allocationBase).second)
            {
                reporter.Add(FindingSeverity::High, L"process/memory",
                    L"Writable executable memory allocation", processId, 0,
                    allocationBase);
            }
            if (memory.Type == MEM_PRIVATE &&
                privateAllocations.insert(allocationBase).second)
            {
                ++suspiciousRegions;
                reporter.Add(IsWritableExecutable(memory.Protect)
                        ? FindingSeverity::High : FindingSeverity::Low,
                    L"process/memory",
                    L"Executable MEM_PRIVATE allocation; JIT/runtime code is possible and content/thread correlation is required",
                    processId, 0, allocationBase);
            }
            else if (memory.Type == MEM_MAPPED &&
                mappedAllocations.insert(allocationBase).second)
            {
                ++suspiciousRegions;
                std::vector<wchar_t> mappedPath(32768);
                (void)GetMappedFileNameW(process, memory.BaseAddress, mappedPath.data(),
                    static_cast<DWORD>(mappedPath.size()));
                reporter.Add(mappedPath[0] == L'\0'
                        ? FindingSeverity::Medium : FindingSeverity::Low,
                    L"process/shared-memory",
                    L"Executable shared/mapped section: " + std::wstring(mappedPath.data()),
                    processId, 0, allocationBase);
            }

            if (unbacked && attempted < kMaximumMemoryScan)
            {
                size_t regionOffset = 0;
                while (regionOffset < memory.RegionSize && attempted < kMaximumMemoryScan)
                {
                    const size_t chunk = std::min<size_t>(
                        {memory.RegionSize - regionOffset, size_t{1024} * 1024,
                         kMaximumMemoryScan - attempted});
                    std::vector<std::byte> bytes(chunk);
                    SIZE_T actual = 0;
                    if (ReadProcessMemory(process,
                            reinterpret_cast<LPCVOID>(base + regionOffset),
                            bytes.data(), bytes.size(), &actual) && actual != 0)
                    {
                        bytes.resize(actual);
                        scanned += actual;
                        for (size_t offset = 0; offset + sizeof(IMAGE_DOS_HEADER) <= bytes.size();
                             offset += 0x1000)
                        {
                            if (LooksLikePe(bytes, offset))
                                reporter.Add(FindingSeverity::Critical, L"process/manual-map",
                                    L"PE image found in executable memory not backed by MEM_IMAGE",
                                    processId, 0, base + regionOffset + offset);
                        }

                        for (size_t offset = 0; offset + 11 <= bytes.size(); ++offset)
                        {
                            const auto* value = reinterpret_cast<const unsigned char*>(bytes.data() + offset);
                            if (value[0] == 0x4C && value[1] == 0x8B && value[2] == 0xD1 &&
                                value[3] == 0xB8 && value[8] == 0x0F && value[9] == 0x05 &&
                                value[10] == 0xC3)
                                reporter.Add(FindingSeverity::High, L"process/syscall-stub",
                                    L"Direct syscall stub found in executable unbacked memory",
                                    processId, 0, base + regionOffset + offset);
                        }

                        std::string lower(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                        std::transform(lower.begin(), lower.end(), lower.begin(),
                            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
                        for (const auto indicator : strings)
                        {
                            size_t match = 0;
                            while ((match = lower.find(indicator, match)) != std::string::npos)
                            {
                                const std::string context = PrintableContext(bytes, match);
                                const uintptr_t foundAddress = base + regionOffset + match;
                                reporter.Add(FindingSeverity::High, L"process/suspect-string",
                                    L"Suspicious string in executable unbacked memory: " + Widen(context),
                                    processId, 0, foundAddress);
                                if (dump) dump << "0x" << std::hex << foundAddress << " " << context << "\r\n";
                                match += indicator.size();
                            }
                        }
                    }
                    attempted += chunk;
                    regionOffset += chunk;
                }
            }
        }
        if (next <= address) break;
        address = next;
    }
    reporter.Add(FindingSeverity::Info, L"process/memory",
        L"Read " + std::to_wstring(scanned) + L" of " +
            std::to_wstring(attempted) + L" attempted executable unbacked bytes; " +
            std::to_wstring(suspiciousRegions) + L" suspicious regions; string dump: " +
            dumpPath.wstring(), processId);
}

bool ParseRemotePe(HANDLE process, const ModuleRecord& module,
    IMAGE_NT_HEADERS64& nt, std::vector<IMAGE_SECTION_HEADER>* sections = nullptr)
{
    IMAGE_DOS_HEADER dos{};
    if (module.size < sizeof(IMAGE_NT_HEADERS64) ||
        !ReadRemote(process, module.base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || static_cast<size_t>(dos.e_lfanew) > module.size - sizeof(nt)) return false;
    if (!ReadRemote(process, module.base + static_cast<uintptr_t>(dos.e_lfanew), nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT ||
        nt.OptionalHeader.SizeOfImage > module.size ||
        nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage)
        return false;
    if (sections != nullptr)
    {
        const size_t count = std::min<size_t>(nt.FileHeader.NumberOfSections, 96);
        sections->resize(count);
        const uintptr_t sectionAddress = module.base + static_cast<uintptr_t>(dos.e_lfanew) +
            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
        const ULONGLONG sectionRva = sectionAddress - module.base;
        if (!RvaRangeValid(module, sectionRva, count * sizeof(IMAGE_SECTION_HEADER)))
            return false;
        if (!ReadRemoteBytes(process, sectionAddress, sections->data(), count * sizeof(IMAGE_SECTION_HEADER)))
            return false;
    }
    return true;
}

void ScanImportsAndIat(HANDLE process, DWORD processId,
    const std::vector<ModuleRecord>& modules, Reporter& reporter)
{
    for (const auto& module : modules)
    {
        /* MEM_IMAGE also includes resource/data-file mappings whose IAT was never
           resolved by the loader.  Only loader-visible modules have live IATs. */
        if (!module.toolhelp && !module.psapi) continue;
        IMAGE_NT_HEADERS64 nt{};
        if (!ParseRemotePe(process, module, nt)) continue;
        const auto& directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (directory.VirtualAddress == 0 || directory.Size == 0 ||
            !RvaRangeValid(module, directory.VirtualAddress, directory.Size)) continue;
        bool importsProtectionApi = false;
        size_t importCount = 0;
        size_t unbackedTargets = 0;
        const size_t maximumDescriptors = std::min<size_t>(
            512,
            directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));
        for (size_t descriptorIndex = 0;
             descriptorIndex < maximumDescriptors;
             ++descriptorIndex)
        {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            const ULONGLONG descriptorRva =
                static_cast<ULONGLONG>(directory.VirtualAddress) +
                descriptorIndex * sizeof(descriptor);
            const uintptr_t descriptorAddress = module.base +
                static_cast<uintptr_t>(descriptorRva);
            if (!ReadRemote(process, descriptorAddress, descriptor) || descriptor.Name == 0) break;
            if (!RvaRangeValid(module, descriptor.Name, 1) || descriptor.FirstThunk == 0)
                continue;
            const std::wstring importedDll = Widen(ReadRemoteAscii(
                process,
                module.base + descriptor.Name,
                std::min<size_t>(512, module.size - descriptor.Name)));
            const DWORD original = descriptor.OriginalFirstThunk != 0
                ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
            for (size_t thunkIndex = 0; thunkIndex < 8192; ++thunkIndex)
            {
                IMAGE_THUNK_DATA64 source{};
                ULONGLONG destination = 0;
                const ULONGLONG sourceRva = static_cast<ULONGLONG>(original) +
                    thunkIndex * sizeof(source);
                const ULONGLONG destinationRva =
                    static_cast<ULONGLONG>(descriptor.FirstThunk) +
                    thunkIndex * sizeof(destination);
                if (!RvaRangeValid(module, sourceRva, sizeof(source)) ||
                    !RvaRangeValid(module, destinationRva, sizeof(destination)) ||
                    !ReadRemote(process, module.base + static_cast<uintptr_t>(sourceRva), source) ||
                    !ReadRemote(process, module.base + static_cast<uintptr_t>(destinationRva), destination) ||
                    source.u1.AddressOfData == 0) break;
                ++importCount;
                if ((source.u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0 &&
                    RvaRangeValid(
                        module,
                        source.u1.AddressOfData,
                        offsetof(IMAGE_IMPORT_BY_NAME, Name) + 1))
                {
                    const ULONGLONG nameRva = source.u1.AddressOfData +
                        offsetof(IMAGE_IMPORT_BY_NAME, Name);
                    const std::string function = ReadRemoteAscii(process,
                        module.base + static_cast<uintptr_t>(nameRva),
                        std::min<size_t>(512,
                            module.size - static_cast<size_t>(nameRva)));
                    const std::string lower = [&]
                    {
                        std::string value = function;
                        std::transform(value.begin(), value.end(), value.begin(),
                            [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
                        return value;
                    }();
                    if (lower == "virtualprotect" || lower == "virtualprotectex" ||
                        lower == "ntprotectvirtualmemory") importsProtectionApi = true;
                }
                if (destination != 0 && !AddressInModules(static_cast<uintptr_t>(destination), modules))
                {
                    ++unbackedTargets;
                    if (unbackedTargets <= 8)
                    {
                        std::wostringstream message;
                        message << L"IAT entry in " << BaseName(module.path) << L" for "
                                << importedDll << L" points outside every known module";
                        reporter.Add(FindingSeverity::High, L"process/hooks", message.str(),
                            processId, 0, module.base + descriptor.FirstThunk +
                                static_cast<uintptr_t>(thunkIndex * sizeof(destination)));
                    }
                }
            }
        }
        if (importsProtectionApi)
            reporter.Add(FindingSeverity::Info, L"process/virtual-protect",
                L"Module imports a memory-protection API: " + module.path,
                processId, 0, module.base);
        if (unbackedTargets != 0)
            reporter.Add(FindingSeverity::High, L"process/hooks",
                L"Module has " + std::to_wstring(unbackedTargets) +
                    L" IAT targets outside loader and memory-image module views: " +
                    module.path,
                processId, 0, module.base);
        if (importCount > 100000)
            reporter.Add(FindingSeverity::Medium, L"process/integrity",
                L"Implausibly large import table in " + module.path, processId, 0, module.base);
    }
}

template<size_t Size>
uintptr_t DecodeJumpTarget(HANDLE process, uintptr_t address,
    const std::array<unsigned char, Size>& code)
{
    static_assert(Size >= 16);
    if (code[0] == 0xEB)
    {
        const auto relative = static_cast<signed char>(code[1]);
        return address + 2 + relative;
    }
    if (code[0] == 0xE9)
    {
        LONG relative = 0;
        memcpy(&relative, code.data() + 1, sizeof(relative));
        return address + 5 + relative;
    }
    if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0)
    {
        uintptr_t absolute = 0;
        memcpy(&absolute, code.data() + 2, sizeof(absolute));
        return absolute;
    }
    if (code[0] == 0x49 && (code[1] & 0xF8) == 0xB8 &&
        code[10] == 0x41 && code[11] == 0xFF &&
        (code[12] & 0xF8) == 0xE0 && (code[1] & 7) == (code[12] & 7))
    {
        uintptr_t absolute = 0;
        memcpy(&absolute, code.data() + 2, sizeof(absolute));
        return absolute;
    }
    if (code[0] == 0xFF && code[1] == 0x25)
    {
        LONG relative = 0;
        uintptr_t target = 0;
        memcpy(&relative, code.data() + 2, sizeof(relative));
        const uintptr_t slot = address + 6 + relative;
        if (ReadRemote(process, slot, target)) return target;
    }
    return 0;
}

enum class ExportCheckKind : unsigned char
{
    None,
    Syscall,
    Detour
};

ExportCheckKind ExportCheck(std::wstring_view module, std::string_view function)
{
    static constexpr std::string_view ntdllSyscalls[] =
    {
        "ntopenprocess", "ntreadvirtualmemory", "ntwritevirtualmemory",
        "ntprotectvirtualmemory", "ntcreatethreadex", "ntquerysysteminformation",
        "ntqueryinformationprocess", "ntsetinformationthread"
    };
    static constexpr std::string_view win32uSyscalls[] =
    {
        "ntusergetasynckeystate", "ntuserquerywindow", "ntuserbuildhwndlist",
        "ntuserfindwindowex", "ntusergetforegroundwindow", "ntgdibitblt"
    };
    static constexpr std::string_view userDetours[] =
    {
        "ldrloaddll", "virtualprotect", "virtualprotectex", "writeprocessmemory",
        "createremotethread", "loadlibraryw", "createdxgifactory",
        "createdxgifactory1", "createdxgifactory2", "d3d11createdevice",
        "d3d11createdeviceandswapchain"
    };
    const auto contains = [function](const auto& values)
    {
        return std::ranges::find(values, function) != std::end(values);
    };
    if (module == L"ntdll.dll" && contains(ntdllSyscalls))
        return ExportCheckKind::Syscall;
    if (module == L"win32u.dll" && contains(win32uSyscalls))
        return ExportCheckKind::Syscall;
    if (contains(userDetours)) return ExportCheckKind::Detour;
    return ExportCheckKind::None;
}

template<size_t Size>
bool LooksLikeSyscallStub(const std::array<unsigned char, Size>& code)
{
    static_assert(Size >= 16);
    size_t offset = 0;
    if (code[0] == 0xF3 && code[1] == 0x0F &&
        code[2] == 0x1E && code[3] == 0xFA)
        offset = 4;
    if (offset + 12 > code.size() || code[offset] != 0x4C ||
        code[offset + 1] != 0x8B || code[offset + 2] != 0xD1 ||
        code[offset + 3] != 0xB8)
        return false;
    for (size_t index = offset + 4; index + 1 < code.size(); ++index)
        if (code[index] == 0x0F && code[index + 1] == 0x05) return true;
    return false;
}

bool ExpectedSystemForwarder(
    std::wstring_view source,
    std::wstring_view destination)
{
    if (source == L"kernel32.dll")
        return destination == L"kernelbase.dll" || destination == L"ntdll.dll";
    if (source == L"kernelbase.dll")
        return destination == L"ntdll.dll" || destination == L"kernel32.dll";
    return false;
}

void ScanExportHooks(HANDLE process, DWORD processId,
    const std::vector<ModuleRecord>& modules, Reporter& reporter)
{
    size_t checked = 0;
    size_t suspicious = 0;
    size_t expectedForwarders = 0;
    for (const auto& module : modules)
    {
        const std::wstring name = Lower(BaseName(module.path));
        if (name != L"ntdll.dll" && name != L"kernel32.dll" &&
            name != L"kernelbase.dll" && name != L"win32u.dll" &&
            name != L"dxgi.dll" && name != L"d3d11.dll") continue;
        IMAGE_NT_HEADERS64 nt{};
        if (!ParseRemotePe(process, module, nt)) continue;
        const auto& directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress == 0 ||
            directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
            !RvaRangeValid(module, directory.VirtualAddress, directory.Size)) continue;
        IMAGE_EXPORT_DIRECTORY exports{};
        if (!ReadRemote(process, module.base + directory.VirtualAddress, exports)) continue;
        const DWORD functionCount = std::min<DWORD>(exports.NumberOfFunctions, 8192);
        const DWORD nameCount = std::min<DWORD>(exports.NumberOfNames, 8192);
        if (!RvaRangeValid(module, exports.AddressOfFunctions,
                static_cast<size_t>(functionCount) * sizeof(DWORD)) ||
            !RvaRangeValid(module, exports.AddressOfNames,
                static_cast<size_t>(nameCount) * sizeof(DWORD)) ||
            !RvaRangeValid(module, exports.AddressOfNameOrdinals,
                static_cast<size_t>(nameCount) * sizeof(WORD)))
            continue;
        for (DWORD nameIndex = 0; nameIndex < nameCount; ++nameIndex)
        {
            DWORD nameRva = 0;
            WORD ordinal = 0;
            DWORD rva = 0;
            if (!ReadRemote(process, module.base + exports.AddressOfNames +
                    nameIndex * sizeof(nameRva), nameRva) ||
                !ReadRemote(process, module.base + exports.AddressOfNameOrdinals +
                    nameIndex * sizeof(ordinal), ordinal) ||
                ordinal >= functionCount || !RvaRangeValid(module, nameRva, 1))
                continue;
            std::string function = ReadRemoteAscii(process, module.base + nameRva, 256);
            std::transform(function.begin(), function.end(), function.begin(),
                [](unsigned char character)
                {
                    return static_cast<char>(std::tolower(character));
                });
            const ExportCheckKind kind = ExportCheck(name, function);
            if (kind == ExportCheckKind::None) continue;
            ++checked;
            if (!ReadRemote(process, module.base + exports.AddressOfFunctions +
                    ordinal * sizeof(rva), rva) || rva == 0 || rva >= module.size)
                continue;
            if (rva >= directory.VirtualAddress &&
                rva - directory.VirtualAddress < directory.Size)
                continue;
            std::array<unsigned char, 32> code{};
            if (!ReadRemoteBytes(process, module.base + rva, code.data(), code.size())) continue;
            const uintptr_t functionAddress = module.base + rva;
            const uintptr_t target = DecodeJumpTarget(process, functionAddress, code);
            if (kind == ExportCheckKind::Syscall && LooksLikeSyscallStub(code)) continue;
            if (kind == ExportCheckKind::Syscall && target == 0)
            {
                ++suspicious;
                reporter.Add(FindingSeverity::Medium, L"process/hooks",
                    L"Sensitive syscall export " + Widen(function) + L" in " + name +
                        L" has a noncanonical prologue",
                    processId, 0, functionAddress);
                continue;
            }
            if (target == 0) continue;

            const ModuleRecord* targetModule = nullptr;
            if (!AddressInModules(target, modules, &targetModule))
            {
                ++suspicious;
                reporter.Add(FindingSeverity::Critical, L"process/hooks",
                    L"Sensitive export " + Widen(function) + L" in " + name +
                        L" detours into unbacked memory",
                    processId, 0, functionAddress);
            }
            else if (targetModule == &module)
            {
                reporter.Add(FindingSeverity::Low, L"process/hooks",
                    L"Sensitive export " + Widen(function) + L" in " + name +
                        L" begins with an intra-module branch",
                    processId, 0, functionAddress);
            }
            else
            {
                const std::wstring targetName = Lower(BaseName(targetModule->path));
                if (ExpectedSystemForwarder(name, targetName))
                {
                    ++expectedForwarders;
                }
                else
                {
                    ++suspicious;
                    reporter.Add(FindingSeverity::High, L"process/hooks",
                        L"Sensitive export " + Widen(function) + L" in " + name +
                            L" detours into " + BaseName(targetModule->path),
                        processId, 0, functionAddress);
                }
            }
        }
    }
    reporter.Add(FindingSeverity::Info, L"process/hooks",
        L"Checked " + std::to_wstring(checked) +
            L" named high-value export prologues; suspicious=" +
            std::to_wstring(suspicious) + L" expected-system-forwarders=" +
            std::to_wstring(expectedForwarders),
        processId);
}

void ScanDebuggerAndInstrumentation(HANDLE process, DWORD processId,
    const std::vector<ModuleRecord>& modules, Reporter& reporter)
{
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(process, &remoteDebugger) && remoteDebugger)
        reporter.Add(FindingSeverity::High, L"process/debugger",
            L"CheckRemoteDebuggerPresent reports a debugger", processId);
    if (IsDebuggerPresent())
        reporter.Add(FindingSeverity::High, L"process/debugger",
            L"The OAC client itself is being debugged", GetCurrentProcessId());

    const auto query = ResolveFunction<NtQueryInformationProcessFn>(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (query == nullptr) return;
    ULONG returned = 0;
    ULONG_PTR debugPort = 0;
    HANDLE debugObject = nullptr;
    ULONG debugFlags = 1;
    if (query(process, kProcessDebugPort, &debugPort, sizeof(debugPort), &returned) >= 0 &&
        debugPort != 0)
        reporter.Add(FindingSeverity::High, L"process/debugger",
            L"ProcessDebugPort is nonzero", processId, 0, debugPort);
    if (query(process, kProcessDebugObjectHandle, static_cast<PVOID>(&debugObject),
            sizeof(debugObject), &returned) >= 0 &&
        debugObject != nullptr)
    {
        reporter.Add(FindingSeverity::High, L"process/debugger",
            L"ProcessDebugObjectHandle is present", processId);
        (void)CloseHandle(debugObject);
    }
    if (query(process, kProcessDebugFlags, &debugFlags, sizeof(debugFlags), &returned) >= 0 &&
        debugFlags == 0)
        reporter.Add(FindingSeverity::High, L"process/debugger",
            L"ProcessDebugFlags indicates an attached debugger", processId);

    InstrumentationCallbackInformation instrumentation{};
    const LONG instrumentationStatus = query(
        process,
        kProcessInstrumentationCallback,
        &instrumentation,
        sizeof(instrumentation),
        &returned);
    if (instrumentationStatus >= 0 && instrumentation.Callback != nullptr)
    {
        const uintptr_t callback = reinterpret_cast<uintptr_t>(instrumentation.Callback);
        reporter.Add(AddressInModules(callback, modules) ? FindingSeverity::Low : FindingSeverity::High,
            L"process/instrumentation",
            AddressInModules(callback, modules)
                ? L"Process instrumentation callback is registered inside a module"
                : L"Process instrumentation callback points outside known modules",
            processId, 0, callback);
    }
    else if (instrumentationStatus >= 0)
    {
        reporter.Add(FindingSeverity::Info, L"process/instrumentation",
            L"No queryable process instrumentation callback is installed", processId);
    }
    else
    {
        std::wostringstream message;
        message << L"Process instrumentation callback query is unavailable (NTSTATUS 0x"
                << std::hex << static_cast<ULONG>(instrumentationStatus) << L')';
        reporter.Add(FindingSeverity::Low, L"process/instrumentation", message.str(), processId);
    }
}

void ScanThreads(HANDLE process, DWORD processId, const std::vector<ModuleRecord>& modules,
    bool applyHardening, Reporter& reporter)
{
    const auto queryThread = ResolveFunction<NtQueryInformationThreadFn>(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    const auto setThread = ResolveFunction<NtSetInformationThreadFn>(
        GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot)
    {
        reporter.Add(FindingSeverity::Medium, L"process/thread",
            L"Unable to create the system thread snapshot", processId);
        return;
    }
    (void)SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
    const bool symbols = SymInitializeW(process, nullptr, TRUE) == TRUE;

    size_t count = 0;
    size_t accessible = 0;
    size_t hardeningAttempts = 0;
    size_t hardeningSuccesses = 0;
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot.get(), &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != processId) continue;
            ++count;
            DWORD threadAccess = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT |
                THREAD_SUSPEND_RESUME;
            if (applyHardening) threadAccess |= THREAD_SET_INFORMATION;
            UniqueHandle thread(OpenThread(threadAccess, FALSE, entry.th32ThreadID));
            if (!thread) continue;
            ++accessible;

            PVOID startAddress = nullptr;
            ULONG returned = 0;
            if (queryThread != nullptr && queryThread(thread.get(), kThreadQuerySetWin32StartAddress,
                    static_cast<PVOID>(&startAddress), sizeof(startAddress), &returned) >= 0 &&
                startAddress != nullptr &&
                !AddressInModules(reinterpret_cast<uintptr_t>(startAddress), modules))
                reporter.Add(FindingSeverity::High, L"process/thread",
                    L"Thread start address is outside every known module",
                    processId, entry.th32ThreadID,
                    reinterpret_cast<uintptr_t>(startAddress));

            DWORD resumeError = ERROR_SUCCESS;
            bool resumeFailedForLiveThread = false;
            {
                oac::ScopedThreadSuspension suspension(thread.get());
                if (suspension.Active())
                {
                    CONTEXT context{};
                    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(thread.get(), &context))
                    {
                        const DWORD64 dr6Status = context.Dr6 & kDr6StatusMask;
                        if ((context.Dr7 & 0xFFULL) != 0 || dr6Status != 0)
                        {
                            std::wostringstream message;
                            message << L"Thread debug registers: DR6-status=0x" << std::hex << dr6Status
                                    << L" DR7=0x" << context.Dr7;
                            reporter.Add((context.Dr7 & 0xFFULL) != 0
                                    ? FindingSeverity::High : FindingSeverity::Low,
                                L"process/debugger", message.str(), processId, entry.th32ThreadID);
                        }

                        STACKFRAME64 frame{};
                        frame.AddrPC.Offset = context.Rip;
                        frame.AddrPC.Mode = AddrModeFlat;
                        frame.AddrFrame.Offset = context.Rbp;
                        frame.AddrFrame.Mode = AddrModeFlat;
                        frame.AddrStack.Offset = context.Rsp;
                        frame.AddrStack.Mode = AddrModeFlat;
                        for (unsigned depth = 0; depth < 64; ++depth)
                        {
                            const DWORD64 address = depth == 0 ? context.Rip : frame.AddrPC.Offset;
                            if (address != 0 && !AddressInModules(static_cast<uintptr_t>(address), modules))
                            {
                                MEMORY_BASIC_INFORMATION memory{};
                                if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address),
                                        &memory, sizeof(memory)) != 0 && IsExecutable(memory.Protect))
                                    reporter.Add(FindingSeverity::High, L"process/stack",
                                        L"Stack frame executes outside every known module",
                                        processId, entry.th32ThreadID, address);
                            }
                            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread.get(), &frame,
                                    &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64,
                                    nullptr) || frame.AddrPC.Offset == 0) break;
                        }
                    }
                    resumeError = suspension.Resume();
                    resumeFailedForLiveThread = resumeError != ERROR_SUCCESS &&
                        WaitForSingleObject(thread.get(), 0) != WAIT_OBJECT_0;
                }
            }
            if (resumeFailedForLiveThread)
            {
                reporter.Add(FindingSeverity::Critical, L"process/thread",
                    L"Could not resume a sampled target thread; error=" +
                        std::to_wstring(resumeError),
                    processId, entry.th32ThreadID);
            }

            if (applyHardening && setThread != nullptr)
            {
                ++hardeningAttempts;
                const LONG status = setThread(thread.get(), kThreadHideFromDebugger, nullptr, 0);
                if (status < 0)
                    reporter.Add(FindingSeverity::Medium, L"hardening",
                        L"ThreadHideFromDebugger failed with NTSTATUS 0x" + [&]
                        {
                            std::wostringstream stream; stream << std::hex << static_cast<ULONG>(status);
                            return stream.str();
                        }(), processId, entry.th32ThreadID);
                else
                    ++hardeningSuccesses;
            }
        } while (Thread32Next(snapshot.get(), &entry));
    }
    if (symbols) SymCleanup(process);
    reporter.Add(FindingSeverity::Info, L"process/thread",
        L"Enumerated, inspected debug registers, and stack-walked " +
            std::to_wstring(accessible) + L" of " + std::to_wstring(count) +
            L" enumerated threads", processId);
    if (applyHardening)
    {
        if (setThread == nullptr)
            reporter.Add(FindingSeverity::Medium, L"hardening",
                L"NtSetInformationThread is unavailable; ThreadHideFromDebugger was skipped",
                processId);
        reporter.Add(FindingSeverity::Info, L"hardening",
            L"ThreadHideFromDebugger succeeded for " +
                std::to_wstring(hardeningSuccesses) + L" of " +
                std::to_wstring(hardeningAttempts) + L" attempted threads",
            processId);
    }
}

bool PatchRemoteBreakin(HANDLE process, DWORD processId,
    const std::vector<ModuleRecord>& modules, Reporter& reporter)
{
    const ModuleRecord* remoteNtdll = nullptr;
    for (const auto& module : modules)
        if (Lower(BaseName(module.path)) == L"ntdll.dll") { remoteNtdll = &module; break; }
    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
    if (remoteNtdll == nullptr || localNtdll == nullptr) return false;
    const FARPROC localBreakin = GetProcAddress(localNtdll, "DbgUiRemoteBreakin");
    if (localBreakin == nullptr) return false;
    uintptr_t localBreakinAddress = 0;
    static_assert(sizeof(localBreakinAddress) == sizeof(localBreakin));
    std::memcpy(&localBreakinAddress, static_cast<const void*>(&localBreakin),
        sizeof(localBreakinAddress));
    const uintptr_t offset = localBreakinAddress -
        reinterpret_cast<uintptr_t>(localNtdll);
    if (offset >= remoteNtdll->size) return false;
    IMAGE_NT_HEADERS64 remoteHeaders{};
    if (!ParseRemotePe(process, *remoteNtdll, remoteHeaders)) return false;
    const uintptr_t remoteAddress = remoteNtdll->base + offset;
    unsigned char original = 0;
    if (!ReadRemote(process, remoteAddress, original)) return false;
    unsigned char expected = 0;
    std::memcpy(&expected, reinterpret_cast<const void*>(localBreakinAddress), sizeof(expected));
    if (original == 0xC3)
    {
        reporter.Add(FindingSeverity::Info, L"hardening",
            L"DbgUiRemoteBreakin was already patched with RET", processId, 0, remoteAddress);
        return true;
    }
    if (original != expected)
    {
        reporter.Add(FindingSeverity::Medium, L"hardening",
            L"DbgUiRemoteBreakin differs from the local same-build image; refusing to overwrite it",
            processId, 0, remoteAddress);
        return false;
    }
    DWORD oldProtection = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(remoteAddress), 1,
            PAGE_EXECUTE_READWRITE, &oldProtection)) return false;
    const unsigned char instruction = 0xC3;
    SIZE_T written = 0;
    const bool writeSucceeded = WriteProcessMemory(
        process,
        reinterpret_cast<LPVOID>(remoteAddress),
        &instruction,
        1,
        &written) && written == 1;
    const bool flushSucceeded = writeSucceeded && FlushInstructionCache(
        process,
        reinterpret_cast<LPCVOID>(remoteAddress),
        1);
    if (!flushSucceeded && written == 1)
    {
        SIZE_T restoredBytes = 0;
        if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(remoteAddress),
                &original, 1, &restoredBytes) || restoredBytes != 1 ||
            !FlushInstructionCache(process, reinterpret_cast<LPCVOID>(remoteAddress), 1))
        {
            reporter.Add(FindingSeverity::Critical, L"hardening",
                L"DbgUiRemoteBreakin patch failed and its original byte could not be restored",
                processId, 0, remoteAddress);
        }
    }
    DWORD ignored = 0;
    const bool protectionRestored = VirtualProtectEx(
        process,
        reinterpret_cast<LPVOID>(remoteAddress),
        1,
        oldProtection,
        &ignored) == TRUE;
    if (!protectionRestored)
        reporter.Add(FindingSeverity::High, L"hardening",
            L"Failed to restore DbgUiRemoteBreakin page protection", processId, 0, remoteAddress);
    const bool success = flushSucceeded && protectionRestored;
    if (success)
    {
        std::wostringstream message;
        message << L"Patched DbgUiRemoteBreakin with RET (original byte 0x"
                << std::hex << static_cast<unsigned>(original) << L")";
        reporter.Add(FindingSeverity::Info, L"hardening", message.str(), processId, 0, remoteAddress);
    }
    return success;
}

struct OverlayContext
{
    DWORD targetPid;
    RECT targetRect;
    bool haveTargetRect;
    Reporter* reporter;
};

BOOL CALLBACK FindTargetWindow(HWND window, LPARAM parameter)
{
    auto& context = *reinterpret_cast<OverlayContext*>(parameter);
    DWORD processId = 0;
    (void)GetWindowThreadProcessId(window, &processId);
    if (processId == context.targetPid && IsWindowVisible(window))
    {
        RECT rectangle{};
        if (GetWindowRect(window, &rectangle) &&
            rectangle.right > rectangle.left && rectangle.bottom > rectangle.top)
        {
            context.targetRect = rectangle;
            context.haveTargetRect = true;
            return FALSE;
        }
    }
    return TRUE;
}

BOOL CALLBACK InspectOverlayWindow(HWND window, LPARAM parameter)
{
    auto& context = *reinterpret_cast<OverlayContext*>(parameter);
    if (!context.haveTargetRect || !IsWindowVisible(window)) return TRUE;
    DWORD processId = 0;
    (void)GetWindowThreadProcessId(window, &processId);
    if (processId == 0 || processId == context.targetPid) return TRUE;
    RECT rectangle{};
    RECT intersection{};
    if (!GetWindowRect(window, &rectangle) ||
        !IntersectRect(&intersection, &rectangle, &context.targetRect)) return TRUE;
    const LONG_PTR style = GetWindowLongPtrW(window, GWL_EXSTYLE);
    const bool overlayStyle = (style & (WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT |
        WS_EX_NOACTIVATE)) != 0;
    if (!overlayStyle) return TRUE;
    wchar_t title[512]{};
    wchar_t className[256]{};
    (void)GetWindowTextW(window, title, static_cast<int>(std::size(title)));
    (void)GetClassNameW(window, className, static_cast<int>(std::size(className)));
    std::wostringstream message;
    message << L"Overlapping topmost/layered/transparent window: class=" << className
            << L" title=" << title << L" style=0x" << std::hex << style;
    context.reporter->Add(FindingSeverity::Medium, L"process/overlay", message.str(), processId);
    return TRUE;
}

void ScanOverlayWindows(DWORD processId, Reporter& reporter)
{
    OverlayContext context{processId, {}, false, &reporter};
    EnumWindows(FindTargetWindow, reinterpret_cast<LPARAM>(&context));
    if (context.haveTargetRect)
        EnumWindows(InspectOverlayWindow, reinterpret_cast<LPARAM>(&context));
    else
        reporter.Add(FindingSeverity::Low, L"process/overlay",
            L"No visible top-level target window was available for overlay comparison", processId);
}
} // namespace

void RunProcessScan(const ScanOptions& options, Reporter& reporter)
{
    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ;
    if (options.applyHardening)
        access |= PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    UniqueHandle process(OpenProcess(access, FALSE, options.targetProcessId));
    if (!process)
    {
        reporter.Add(FindingSeverity::Critical, L"process",
            L"Unable to open the target process with scanning rights", options.targetProcessId);
        return;
    }

    if (!IsSupportedTargetArchitecture(process.get(), options.targetProcessId, reporter))
        return;

    const auto modules = EnumerateModules(process.get(), options.targetProcessId, reporter);
    ScanUnbackedMemory(process.get(), options.targetProcessId, options, reporter);
    ScanImportsAndIat(process.get(), options.targetProcessId, modules, reporter);
    ScanExportHooks(process.get(), options.targetProcessId, modules, reporter);
    ScanDebuggerAndInstrumentation(process.get(), options.targetProcessId, modules, reporter);
    ScanThreads(process.get(), options.targetProcessId, modules, options.applyHardening, reporter);
    ScanOverlayWindows(options.targetProcessId, reporter);

    if (options.applyHardening && !PatchRemoteBreakin(
            process.get(), options.targetProcessId, modules, reporter))
        reporter.Add(FindingSeverity::Medium, L"hardening",
            L"DbgUiRemoteBreakin patch could not be applied", options.targetProcessId);
}
