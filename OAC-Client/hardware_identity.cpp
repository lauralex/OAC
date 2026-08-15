#include "scanner.hpp"

#include <SetupAPI.h>
#include <bcrypt.h>
#include <batclass.h>
#include <bluetoothapis.h>
#include <devguid.h>
#include <hidsdi.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <nvme.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cwctype>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <sstream>
#include <string_view>
#include <vector>

namespace
{
constexpr DWORD FirmwareProvider(char a, char b, char c, char d) noexcept
{
    return (static_cast<DWORD>(static_cast<unsigned char>(a)) << 24) |
        (static_cast<DWORD>(static_cast<unsigned char>(b)) << 16) |
        (static_cast<DWORD>(static_cast<unsigned char>(c)) << 8) |
        static_cast<DWORD>(static_cast<unsigned char>(d));
}

constexpr DWORD kRawSmbiosProvider = FirmwareProvider('R', 'S', 'M', 'B');
constexpr DWORD kAcpiProvider = FirmwareProvider('A', 'C', 'P', 'I');
constexpr DWORD kMountdevControlType = 0x4D;
constexpr DWORD kIoctlMountdevQueryUniqueId =
    CTL_CODE(kMountdevControlType, 0, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD kIoctlMountdevQueryStableGuid =
    CTL_CODE(kMountdevControlType, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr size_t kMaximumIdentityValue = size_t{64} * 1024;
constexpr GUID kBatteryInterface = {
    0x72631E54, 0x78A4, 0x11D0, {0xBC, 0xF7, 0x00, 0xAA, 0x00, 0xB7, 0xB3, 0x2A}};
constexpr DEVPROPKEY kDeviceLocationPaths = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 37};
constexpr DEVPROPKEY kDeviceBaseContainerId = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 38};
constexpr DEVPROPKEY kDeviceContainerId = {
    {0x8C7ED206, 0x3F8A, 0x4827, {0xB3, 0xAB, 0xAE, 0x9E, 0x1F, 0xAE, 0xFC, 0x6C}}, 2};
constexpr DEVPROPKEY kDeviceExtendedAddress = {
    {0x540B947E, 0x8B40, 0x45BC, {0xA8, 0xA2, 0x6A, 0x0B, 0x89, 0x4C, 0xBD, 0xA2}}, 23};

enum class IdentityStrength : unsigned char
{
    Context,
    Weak,
    Medium,
    Strong
};

struct IdentitySignal
{
    std::wstring category;
    std::wstring source;
    std::wstring label;
    std::wstring group;
    std::wstring value;
    IdentityStrength strength = IdentityStrength::Context;
    bool stable = false;
    bool comparable = false;
    bool peripheral = false;
};

class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
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

class UniqueDevInfo
{
public:
    explicit UniqueDevInfo(HDEVINFO set = INVALID_HANDLE_VALUE) noexcept : set_(set) {}
    ~UniqueDevInfo()
    {
        if (set_ != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(set_);
    }
    UniqueDevInfo(const UniqueDevInfo&) = delete;
    UniqueDevInfo& operator=(const UniqueDevInfo&) = delete;
    HDEVINFO get() const noexcept { return set_; }
    explicit operator bool() const noexcept { return set_ != INVALID_HANDLE_VALUE; }

private:
    HDEVINFO set_;
};

class UniqueRegKey
{
public:
    explicit UniqueRegKey(HKEY key = nullptr) noexcept : key_(key) {}
    ~UniqueRegKey() { if (key_ != nullptr) RegCloseKey(key_); }
    UniqueRegKey(const UniqueRegKey&) = delete;
    UniqueRegKey& operator=(const UniqueRegKey&) = delete;
    HKEY get() const noexcept { return key_; }
    explicit operator bool() const noexcept { return key_ != nullptr; }

private:
    HKEY key_;
};

void Wipe(std::wstring& value) noexcept
{
    if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    value.clear();
}

std::wstring TrimAndNormalize(std::wstring_view input)
{
    size_t first = 0;
    while (first < input.size() && (input[first] == L'\0' || std::iswspace(input[first]))) ++first;
    size_t last = input.size();
    while (last > first && (input[last - 1] == L'\0' || std::iswspace(input[last - 1]))) --last;

    std::wstring result;
    result.reserve(last - first);
    bool pendingSpace = false;
    for (size_t index = first; index < last; ++index)
    {
        const wchar_t character = input[index];
        if (character == L'\0' || std::iswspace(character))
        {
            pendingSpace = !result.empty();
            continue;
        }
        if (!std::iswprint(character)) continue;
        if (pendingSpace)
        {
            result.push_back(L' ');
            pendingSpace = false;
        }
        result.push_back(static_cast<wchar_t>(std::towupper(character)));
    }
    return result;
}

std::wstring Alphanumeric(std::wstring_view input)
{
    std::wstring result;
    result.reserve(input.size());
    for (const wchar_t character : input)
    {
        if (std::iswalnum(character))
            result.push_back(static_cast<wchar_t>(std::towupper(character)));
    }
    return result;
}

bool IsPlaceholder(std::wstring_view normalized)
{
    const std::wstring compact = Alphanumeric(normalized);
    if (compact.empty()) return true;
    static const std::set<std::wstring> placeholders = {
        L"0", L"00", L"00000000", L"FFFFFFFF", L"NONE", L"NULL", L"UNKNOWN",
        L"UNSPECIFIED", L"DEFAULT", L"DEFAULTSTRING", L"NOTAPPLICABLE", L"NA",
        L"NOTAVAILABLE", L"NOTSPECIFIED", L"SYSTEMSERIALNUMBER", L"SERIALNUMBER",
        L"TOBEFILLEDBYOEM", L"OEM", L"OEMSTRING", L"INVALID", L"NOASSETTAG"
    };
    if (placeholders.contains(compact)) return true;
    if (compact.find(L"TOBEFILLEDBY") != std::wstring::npos ||
        compact.find(L"DEFAULTSTRING") != std::wstring::npos ||
        compact.find(L"NOTSPECIFIED") != std::wstring::npos) return true;
    if (compact.size() >= 4)
    {
        const wchar_t first = compact.front();
        if ((first == L'0' || first == L'F' || first == L'X' || first == L'?') &&
            std::all_of(compact.begin(), compact.end(),
                [first](wchar_t value) { return value == first; })) return true;
    }
    return false;
}

bool AllByte(std::span<const std::byte> data, std::byte value)
{
    return !data.empty() && std::all_of(data.begin(), data.end(),
        [value](std::byte current) { return current == value; });
}

std::wstring BytesToHex(std::span<const std::byte> data)
{
    static constexpr wchar_t digits[] = L"0123456789ABCDEF";
    if (data.size() > kMaximumIdentityValue) return {};
    std::wstring result(data.size() * 2, L'0');
    for (size_t index = 0; index < data.size(); ++index)
    {
        const unsigned value = std::to_integer<unsigned char>(data[index]);
        result[index * 2] = digits[value >> 4];
        result[index * 2 + 1] = digits[value & 0xF];
    }
    return result;
}

std::wstring Sha256Hex(std::span<const std::byte> data)
{
    if (data.size() > std::numeric_limits<ULONG>::max()) return {};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD digestLength = 0;
    DWORD returned = 0;
    std::vector<UCHAR> object;
    std::vector<UCHAR> digest;
    std::wstring result;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return {};
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digestLength), sizeof(digestLength), &returned, 0) < 0)
        goto Cleanup;
    object.resize(objectLength);
    digest.resize(digestLength);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0)
        goto Cleanup;
    if (!data.empty() && BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())),
            static_cast<ULONG>(data.size()), 0) < 0)
        goto Cleanup;
    if (BCryptFinishHash(hash, digest.data(), digestLength, 0) < 0) goto Cleanup;
    result = BytesToHex(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(digest.data()), digest.size()));

Cleanup:
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!object.empty()) SecureZeroMemory(object.data(), object.size());
    if (!digest.empty()) SecureZeroMemory(digest.data(), digest.size());
    return result;
}

std::wstring GuidText(const GUID& guid)
{
    wchar_t buffer[64]{};
    return StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer))) > 0
        ? std::wstring(buffer)
        : std::wstring{};
}

bool IsZeroGuid(const GUID& guid)
{
    static constexpr GUID zero{};
    return InlineIsEqualGUID(guid, zero) != FALSE;
}

std::wstring CanonicalAnchorGroup(std::wstring group)
{
    static constexpr std::wstring_view prefixes[] = {
        L"disk", L"volume", L"pnp", L"network", L"monitor", L"bluetooth"
    };
    for (const auto prefix : prefixes)
    {
        if (!group.starts_with(prefix)) continue;
        size_t index = prefix.size();
        while (index < group.size() && group[index] >= L'0' && group[index] <= L'9') ++index;
        if (index > prefix.size() && index < group.size() && group[index] == L'/')
        {
            group = std::wstring(prefix) + group.substr(index);
            break;
        }
    }
    if (group.find(L"/id/") != std::wstring::npos)
    {
        const size_t slash = group.rfind(L'/');
        if (slash != std::wstring::npos && slash + 1 < group.size() &&
            std::all_of(group.begin() + static_cast<std::ptrdiff_t>(slash + 1), group.end(),
                [](wchar_t value) { return value >= L'0' && value <= L'9'; }))
            group.erase(slash);
    }
    return group;
}

class IdentityCollector
{
public:
    ~IdentityCollector()
    {
        for (auto& signal : signals_) Wipe(signal.value);
    }

    void Add(
        std::wstring category,
        std::wstring source,
        std::wstring label,
        std::wstring rawValue,
        IdentityStrength strength,
        bool stable,
        std::wstring group = {},
        bool comparable = false,
        bool peripheral = false)
    {
        std::wstring value = TrimAndNormalize(rawValue);
        Wipe(rawValue);
        if (value.empty() || value.size() > kMaximumIdentityValue || IsPlaceholder(value))
        {
            ++rejected_;
            Wipe(value);
            return;
        }
        std::wstring key = source + L"\n" + label + L"\n" + value;
        const std::wstring keyDigest = Sha256Hex(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(key.data()), key.size() * sizeof(wchar_t)));
        Wipe(key);
        if (keyDigest.empty() || !dedup_.insert(keyDigest).second)
        {
            Wipe(value);
            return;
        }
        signals_.push_back({std::move(category), std::move(source), std::move(label),
            std::move(group), std::move(value), strength, stable, comparable, peripheral});
    }

    void AddBinary(
        std::wstring category,
        std::wstring source,
        std::wstring label,
        std::span<const std::byte> data,
        IdentityStrength strength,
        bool stable,
        std::wstring group = {},
        bool comparable = false,
        bool peripheral = false)
    {
        if (data.empty() || data.size() > kMaximumIdentityValue ||
            AllByte(data, std::byte{0}) || AllByte(data, std::byte{0xFF}))
        {
            ++rejected_;
            return;
        }
        Add(std::move(category), std::move(source), std::move(label), BytesToHex(data),
            strength, stable, std::move(group), comparable, peripheral);
    }

    void AddDigest(
        std::wstring category,
        std::wstring source,
        std::wstring label,
        std::span<const std::byte> data,
        IdentityStrength strength,
        bool stable,
        std::wstring group = {})
    {
        const std::wstring digest = Sha256Hex(data);
        if (digest.empty())
        {
            ++rejected_;
            return;
        }
        Add(std::move(category), std::move(source), std::move(label), digest,
            strength, stable, std::move(group));
    }

    void MarkPeripheralGroupPrefix(std::wstring_view prefix)
    {
        for (auto& signal : signals_)
        {
            if (signal.group.starts_with(prefix)) signal.peripheral = true;
        }
    }

    void Report(Reporter& reporter)
    {
        std::map<std::wstring, size_t> categoryCounts;
        std::map<std::wstring, std::set<std::wstring>> groupValues;
        std::map<std::wstring, std::set<std::wstring>> groupSources;
        std::map<std::wstring, std::set<std::wstring>> comparableValues;
        std::map<std::wstring, std::set<std::wstring>> comparableSources;
        std::set<std::wstring> anchorLines;
        size_t strong = 0;
        size_t peripheral = 0;
        for (const auto& signal : signals_)
        {
            ++categoryCounts[signal.category];
            if (signal.strength == IdentityStrength::Strong) ++strong;
            if (signal.peripheral) ++peripheral;
            if (!signal.group.empty())
            {
                std::wstring comparison = signal.comparable
                    ? Alphanumeric(signal.value) : signal.value;
                const std::wstring valueDigest = Sha256Hex(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(comparison.data()),
                    comparison.size() * sizeof(wchar_t)));
                if (!valueDigest.empty()) groupValues[signal.group].insert(valueDigest);
                groupSources[signal.group].insert(signal.source);
                if (signal.comparable && !valueDigest.empty())
                {
                    comparableValues[signal.group].insert(valueDigest);
                    comparableSources[signal.group].insert(signal.source);
                }
                Wipe(comparison);
            }
            if (signal.stable && signal.strength >= IdentityStrength::Medium && !signal.peripheral)
            {
                const std::wstring identity = signal.group.empty()
                    ? signal.category + L"/" + signal.label
                    : CanonicalAnchorGroup(signal.group);
                std::wstring component = identity + L"=" + signal.value;
                const std::wstring componentDigest = Sha256Hex(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(component.data()),
                    component.size() * sizeof(wchar_t)));
                Wipe(component);
                if (!componentDigest.empty()) anchorLines.insert(componentDigest);
            }
        }

        size_t corroborated = 0;
        size_t conflicts = 0;
        for (const auto& [group, values] : groupValues)
        {
            const auto sources = groupSources.find(group);
            if (sources == groupSources.end() || sources->second.size() < 2) continue;
            if (values.size() == 1) ++corroborated;
            const auto comparableGroupValues = comparableValues.find(group);
            const auto comparableGroupSources = comparableSources.find(group);
            if (comparableGroupValues != comparableValues.end() &&
                comparableGroupSources != comparableSources.end() &&
                comparableGroupSources->second.size() >= 2 &&
                comparableGroupValues->second.size() > 1)
            {
                ++conflicts;
                std::wstring sourceList;
                for (const auto& source : comparableGroupSources->second)
                {
                    if (!sourceList.empty()) sourceList += L", ";
                    sourceList += source;
                }
                std::wstring message = L"Independent identity sources disagree for group ";
                message += group;
                message += L"; sources=";
                message += sourceList;
                message += L" (raw values withheld)";
                reporter.Add(FindingSeverity::Medium, L"hwid/consistency", message);
            }
        }

        std::wstring material = L"OAC-HARDWARE-IDENTITY-V3\n";
        for (const auto& line : anchorLines)
        {
            material += line;
            material += L'\n';
        }
        const auto bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(material.data()),
            material.size() * sizeof(wchar_t));
        const std::wstring composite = Sha256Hex(bytes);

        std::wostringstream summary;
        summary << L"Collected " << signals_.size() << L" validated identity signals across "
                << categoryCounts.size() << L" categories; stable anchors=" << anchorLines.size()
                << L", strong signals=" << strong << L", corroborated groups=" << corroborated
                << L", consistency conflicts=" << conflicts
                << L", peripheral-only signals=" << peripheral
                << L", rejected placeholders/empty values=" << rejected_;
        reporter.Add(anchorLines.size() >= 6 ? FindingSeverity::Info : FindingSeverity::Medium,
            L"hwid/coverage", summary.str());

        for (const auto& [category, count] : categoryCounts)
            reporter.Add(FindingSeverity::Info, L"hwid/coverage",
                category + L": " + std::to_wstring(count) + L" validated signals");

        if (composite.empty() || anchorLines.empty())
        {
            reporter.Add(FindingSeverity::Medium, L"hwid",
                L"Unable to calculate a privacy-preserving composite hardware identity");
        }
        else
        {
            reporter.Add(FindingSeverity::Info, L"hwid",
                L"Privacy-preserving hardware identity v3 (SHA-256): " + composite +
                L"; raw component values are intentionally not logged");
        }

        Wipe(material);
    }

private:
    std::vector<IdentitySignal> signals_;
    std::set<std::wstring> dedup_;
    size_t rejected_ = 0;
};

std::vector<std::byte> RegistryValue(HKEY root, const wchar_t* path, const wchar_t* name, DWORD& type)
{
    type = REG_NONE;
    HKEY raw = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &raw) != ERROR_SUCCESS)
        return {};
    UniqueRegKey key(raw);
    DWORD bytes = 0;
    if (RegQueryValueExW(key.get(), name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        bytes == 0 || bytes > 1024 * 1024)
        return {};
    std::vector<std::byte> value(bytes + sizeof(wchar_t) * 2);
    DWORD actual = bytes;
    if (RegQueryValueExW(key.get(), name, nullptr, &type,
            reinterpret_cast<BYTE*>(value.data()), &actual) != ERROR_SUCCESS)
        return {};
    value.resize(actual);
    return value;
}

std::wstring RegistryText(HKEY root, const wchar_t* path, const wchar_t* name)
{
    DWORD type = REG_NONE;
    auto value = RegistryValue(root, path, name, type);
    if (value.empty() || (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ))
    {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
        return {};
    }
    if ((value.size() % sizeof(wchar_t)) != 0)
    {
        SecureZeroMemory(value.data(), value.size());
        return {};
    }
    const size_t characters = value.size() / sizeof(wchar_t);
    std::vector<wchar_t> text(characters + 1);
    memcpy(text.data(), value.data(), value.size());
    std::wstring result;
    if (type == REG_MULTI_SZ)
    {
        size_t offset = 0;
        while (offset < characters && text[offset] != L'\0')
        {
            const size_t length = wcsnlen_s(text.data() + offset, characters - offset);
            if (length == characters - offset) break;
            if (!result.empty()) result += L" | ";
            result.append(text.data() + offset, length);
            offset += length + 1;
        }
    }
    else
    {
        result.assign(text.data(), wcsnlen_s(text.data(), characters));
    }
    SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    return result;
}

void CollectRegistryIdentity(IdentityCollector& collector)
{
    struct RegistryField
    {
        const wchar_t* path;
        const wchar_t* name;
        const wchar_t* label;
        const wchar_t* group;
        IdentityStrength strength;
        bool comparable;
    };
    static constexpr RegistryField fields[] = {
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", L"system manufacturer", L"system/manufacturer", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName", L"system product", L"system/product", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemVersion", L"system version", L"system/version", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemSKU", L"system SKU", L"system/sku", IdentityStrength::Medium, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemFamily", L"system family", L"system/family", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardManufacturer", L"baseboard manufacturer", L"baseboard/manufacturer", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardProduct", L"baseboard product", L"baseboard/product", IdentityStrength::Medium, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BaseBoardVersion", L"baseboard version", L"baseboard/version", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor", L"BIOS vendor", L"bios/vendor", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion", L"BIOS version", L"bios/version", IdentityStrength::Weak, true},
        {L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSReleaseDate", L"BIOS release date", L"bios/date", IdentityStrength::Weak, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareId", L"computer hardware ID", L"system/computer-hardware-id", IdentityStrength::Medium, false},
        {L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareIds", L"computer hardware ID set", L"system/computer-hardware-ids", IdentityStrength::Medium, false},
        {L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", L"installation machine GUID", L"software/machine-guid", IdentityStrength::Weak, false},
    };
    for (const auto& field : fields)
    {
        collector.Add(L"registry", L"registry", field.label,
            RegistryText(HKEY_LOCAL_MACHINE, field.path, field.name), field.strength, true,
            field.group, field.comparable);
    }
}

#pragma pack(push, 1)
struct RawSmbiosData
{
    BYTE used20CallingMethod;
    BYTE majorVersion;
    BYTE minorVersion;
    BYTE dmiRevision;
    DWORD length;
    BYTE table[1];
};

struct SmbiosStructureHeader
{
    BYTE type;
    BYTE length;
    USHORT handle;
};
#pragma pack(pop)

std::wstring SmbiosIndexedString(
    const BYTE* structureEnd,
    const BYTE* tableEnd,
    BYTE index)
{
    if (index == 0) return {};
    const char* current = reinterpret_cast<const char*>(structureEnd);
    const char* end = reinterpret_cast<const char*>(tableEnd);
    for (BYTE number = 1; number <= index && current < end; ++number)
    {
        const size_t remaining = static_cast<size_t>(end - current);
        const size_t length = strnlen_s(current, remaining);
        if (length == remaining) return {};
        if (number == index)
        {
            std::wstring result(length, L'\0');
            for (size_t offset = 0; offset < length; ++offset)
                result[offset] = static_cast<unsigned char>(current[offset]);
            return result;
        }
        current += length + 1;
    }
    return {};
}

std::wstring SmbiosString(
    const BYTE* formatted,
    size_t formattedLength,
    const BYTE* structureEnd,
    const BYTE* tableEnd,
    size_t fieldOffset)
{
    if (fieldOffset >= formattedLength) return {};
    return SmbiosIndexedString(structureEnd, tableEnd, formatted[fieldOffset]);
}

std::wstring HandleLabel(USHORT handle)
{
    std::wostringstream stream;
    stream << std::hex << std::uppercase << handle;
    return stream.str();
}

void CollectSmbios(IdentityCollector& collector, Reporter& reporter)
{
    const UINT required = GetSystemFirmwareTable(kRawSmbiosProvider, 0, nullptr, 0);
    if (required < offsetof(RawSmbiosData, table) || required > 16 * 1024 * 1024)
    {
        reporter.Add(FindingSeverity::Medium, L"hwid/smbios",
            L"Raw SMBIOS firmware data is unavailable or has an invalid size");
        return;
    }
    std::vector<std::byte> buffer(required);
    const UINT written = GetSystemFirmwareTable(kRawSmbiosProvider, 0, buffer.data(), required);
    if (written < offsetof(RawSmbiosData, table) || written > buffer.size())
    {
        reporter.Add(FindingSeverity::Medium, L"hwid/smbios",
            L"Raw SMBIOS firmware query returned malformed data");
        return;
    }
    buffer.resize(written);
    const auto* raw = reinterpret_cast<const RawSmbiosData*>(buffer.data());
    const size_t headerSize = offsetof(RawSmbiosData, table);
    if (raw->length > buffer.size() - headerSize)
    {
        reporter.Add(FindingSeverity::Medium, L"hwid/smbios",
            L"Raw SMBIOS table length exceeds the firmware response");
        return;
    }
    const BYTE* cursor = raw->table;
    const BYTE* tableEnd = cursor + raw->length;
    collector.AddDigest(L"firmware", L"SMBIOS", L"raw SMBIOS table digest",
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(cursor), raw->length),
        IdentityStrength::Medium, true, L"firmware/smbios-digest");

    size_t structures = 0;
    while (cursor + sizeof(SmbiosStructureHeader) <= tableEnd && structures < 4096)
    {
        const auto* header = reinterpret_cast<const SmbiosStructureHeader*>(cursor);
        if (header->length < sizeof(SmbiosStructureHeader) || cursor + header->length > tableEnd)
            break;
        const BYTE* formattedEnd = cursor + header->length;
        const std::wstring handle = HandleLabel(header->handle);
        const auto addString = [&](size_t offset, const wchar_t* label, IdentityStrength strength,
                                   bool stable, std::wstring group = {}, bool comparable = false,
                                   bool peripheral = false)
        {
            collector.Add(L"smbios", L"SMBIOS type " + std::to_wstring(header->type),
                std::wstring(label) + L" [" + handle + L"]",
                SmbiosString(cursor, header->length, formattedEnd, tableEnd, offset),
                strength, stable, std::move(group), comparable, peripheral);
        };

        switch (header->type)
        {
        case 0:
            addString(4, L"BIOS vendor", IdentityStrength::Weak, true, L"bios/vendor", true);
            addString(5, L"BIOS version", IdentityStrength::Weak, true, L"bios/version", true);
            addString(8, L"BIOS release date", IdentityStrength::Weak, true, L"bios/date");
            break;
        case 1:
            addString(4, L"system manufacturer", IdentityStrength::Weak, true, L"system/manufacturer", true);
            addString(5, L"system product", IdentityStrength::Weak, true, L"system/product", true);
            addString(6, L"system version", IdentityStrength::Weak, true, L"system/version", true);
            addString(7, L"system serial", IdentityStrength::Strong, true, L"system/serial", true);
            if (header->length >= 24)
            {
                GUID uuid{};
                memcpy(&uuid, cursor + 8, sizeof(uuid));
                if (!IsZeroGuid(uuid) && !AllByte(
                        std::span<const std::byte>(reinterpret_cast<const std::byte*>(cursor + 8), 16),
                        std::byte{0xFF}))
                    collector.Add(L"smbios", L"SMBIOS type 1", L"system UUID", GuidText(uuid),
                        IdentityStrength::Strong, true, L"system/uuid", true);
            }
            addString(25, L"system SKU", IdentityStrength::Medium, true, L"system/sku", true);
            addString(26, L"system family", IdentityStrength::Weak, true, L"system/family", true);
            break;
        case 2:
            addString(4, L"baseboard manufacturer", IdentityStrength::Weak, true, L"baseboard/manufacturer", true);
            addString(5, L"baseboard product", IdentityStrength::Medium, true, L"baseboard/product", true);
            addString(6, L"baseboard version", IdentityStrength::Weak, true, L"baseboard/version", true);
            addString(7, L"baseboard serial", IdentityStrength::Strong, true, L"baseboard/serial", true);
            addString(8, L"baseboard asset tag", IdentityStrength::Medium, true, L"baseboard/asset-tag");
            addString(10, L"baseboard location", IdentityStrength::Weak, true);
            break;
        case 3:
            addString(4, L"chassis manufacturer", IdentityStrength::Weak, true);
            addString(6, L"chassis version", IdentityStrength::Weak, true);
            addString(7, L"chassis serial", IdentityStrength::Strong, true, L"chassis/serial", true);
            addString(8, L"chassis asset tag", IdentityStrength::Medium, true, L"chassis/asset-tag");
            break;
        case 4:
            addString(4, L"processor socket", IdentityStrength::Weak, true);
            addString(7, L"processor manufacturer", IdentityStrength::Weak, true);
            if (header->length >= 16)
                collector.AddBinary(L"smbios", L"SMBIOS type 4", L"processor ID [" + handle + L"]",
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(cursor + 8), 8),
                    IdentityStrength::Medium, true, L"processor/" + handle + L"/id");
            addString(16, L"processor version", IdentityStrength::Weak, true);
            addString(32, L"processor serial", IdentityStrength::Strong, true,
                L"processor/" + handle + L"/serial", true);
            addString(33, L"processor asset tag", IdentityStrength::Medium, true,
                L"processor/" + handle + L"/asset");
            addString(34, L"processor part number", IdentityStrength::Medium, true,
                L"processor/" + handle + L"/part");
            break;
        case 11:
            if (header->length > 4)
            {
                const BYTE count = std::min<BYTE>(cursor[4], 32);
                for (BYTE index = 1; index <= count; ++index)
                    collector.Add(L"smbios", L"SMBIOS type 11", L"OEM string " + std::to_wstring(index),
                        SmbiosIndexedString(formattedEnd, tableEnd, index),
                        IdentityStrength::Context, true);
            }
            break;
        case 17:
            addString(16, L"memory locator", IdentityStrength::Weak, true);
            addString(17, L"memory bank locator", IdentityStrength::Weak, true);
            addString(23, L"memory manufacturer", IdentityStrength::Weak, true);
            addString(24, L"memory serial", IdentityStrength::Strong, true,
                L"memory/" + handle + L"/serial", true);
            addString(25, L"memory asset tag", IdentityStrength::Medium, true,
                L"memory/" + handle + L"/asset");
            addString(26, L"memory part number", IdentityStrength::Medium, true,
                L"memory/" + handle + L"/part");
            break;
        case 22:
            addString(4, L"battery location", IdentityStrength::Weak, true, {}, false, true);
            addString(5, L"battery manufacturer", IdentityStrength::Weak, true, {}, false, true);
            addString(7, L"battery serial", IdentityStrength::Medium, true,
                L"battery/" + handle + L"/serial", true, true);
            addString(8, L"battery device name", IdentityStrength::Weak, true, {}, false, true);
            if (header->length >= 18)
            {
                USHORT smartBatterySerial = 0;
                memcpy(&smartBatterySerial, cursor + 16, sizeof(smartBatterySerial));
                if (smartBatterySerial != 0)
                    collector.Add(L"smbios", L"SMBIOS type 22", L"smart-battery serial [" + handle + L"]",
                        std::to_wstring(smartBatterySerial), IdentityStrength::Medium, true,
                        L"battery/" + handle + L"/smart-serial", true, true);
            }
            break;
        case 39:
            addString(5, L"power-supply location", IdentityStrength::Weak, true, {}, false, true);
            addString(7, L"power-supply manufacturer", IdentityStrength::Weak, true, {}, false, true);
            addString(8, L"power-supply serial", IdentityStrength::Medium, true,
                L"power-supply/" + handle + L"/serial", true, true);
            addString(9, L"power-supply asset tag", IdentityStrength::Weak, true,
                L"power-supply/" + handle + L"/asset", false, true);
            addString(10, L"power-supply model", IdentityStrength::Weak, true, {}, false, true);
            break;
        case 43:
            if (header->length >= 18)
            {
                collector.AddBinary(L"smbios", L"SMBIOS type 43", L"TPM vendor",
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(cursor + 4), 4),
                    IdentityStrength::Weak, true, L"tpm/vendor");
                collector.AddBinary(L"smbios", L"SMBIOS type 43", L"TPM firmware",
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(cursor + 10), 8),
                    IdentityStrength::Weak, true, L"tpm/firmware");
            }
            break;
        case 45:
            addString(4, L"firmware component", IdentityStrength::Weak, true);
            addString(5, L"firmware component version", IdentityStrength::Weak, true);
            addString(7, L"firmware component ID", IdentityStrength::Medium, true,
                L"firmware/component/" + handle + L"/id");
            addString(10, L"firmware manufacturer", IdentityStrength::Weak, true);
            break;
        default:
            break;
        }

        const BYTE* next = formattedEnd;
        bool terminated = false;
        while (next + 1 < tableEnd)
        {
            if (next[0] == 0 && next[1] == 0)
            {
                next += 2;
                terminated = true;
                break;
            }
            ++next;
        }
        ++structures;
        if (!terminated || next <= cursor) break;
        cursor = next;
        if (header->type == 127) break;
    }
    reporter.Add(FindingSeverity::Info, L"hwid/smbios",
        L"Parsed " + std::to_wstring(structures) + L" bounded SMBIOS structures (version " +
        std::to_wstring(raw->majorVersion) + L'.' + std::to_wstring(raw->minorVersion) + L')');
    SecureZeroMemory(buffer.data(), buffer.size());
}

std::wstring AnsiField(const std::byte* data, size_t size, DWORD offset)
{
    if (offset == 0 || offset >= size) return {};
    const char* text = reinterpret_cast<const char*>(data + offset);
    const size_t length = strnlen_s(text, size - offset);
    if (length == size - offset) return {};
    std::wstring result(length, L'\0');
    for (size_t index = 0; index < length; ++index)
        result[index] = static_cast<unsigned char>(text[index]);
    return result;
}

std::wstring FixedAnsi(const UCHAR* data, size_t size)
{
    std::wstring result(size, L'\0');
    for (size_t index = 0; index < size; ++index)
        result[index] = static_cast<unsigned char>(data[index]);
    return TrimAndNormalize(result);
}

std::vector<std::byte> QueryStorage(HANDLE device, STORAGE_PROPERTY_ID property, BYTE parameter = 0)
{
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = property;
    query.QueryType = PropertyStandardQuery;
    query.AdditionalParameters[0] = parameter;
    std::vector<std::byte> output(size_t{128} * 1024);
    DWORD returned = 0;
    if (!DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY,
            &query, sizeof(query), output.data(), static_cast<DWORD>(output.size()),
            &returned, nullptr) || returned < sizeof(STORAGE_DESCRIPTOR_HEADER) ||
        returned > output.size())
        return {};
    output.resize(returned);
    return output;
}

void CollectStorageDeviceDescriptor(
    IdentityCollector& collector,
    HANDLE disk,
    const std::wstring& diskLabel)
{
    auto output = QueryStorage(disk, StorageDeviceProperty);
    if (output.size() < sizeof(STORAGE_DEVICE_DESCRIPTOR))
    {
        if (!output.empty()) SecureZeroMemory(output.data(), output.size());
        return;
    }
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(output.data());
    const size_t bounded = descriptor->Size >= sizeof(STORAGE_DEVICE_DESCRIPTOR)
        ? std::min<size_t>(descriptor->Size, output.size())
        : output.size();
    collector.Add(L"storage", diskLabel + L" StorageDeviceProperty", L"device serial",
        AnsiField(output.data(), bounded, descriptor->SerialNumberOffset),
        IdentityStrength::Strong, true, diskLabel + L"/controller-serial", true);
    collector.Add(L"storage", diskLabel + L" StorageDeviceProperty", L"vendor",
        AnsiField(output.data(), bounded, descriptor->VendorIdOffset),
        IdentityStrength::Weak, true, diskLabel + L"/vendor");
    collector.Add(L"storage", diskLabel + L" StorageDeviceProperty", L"product",
        AnsiField(output.data(), bounded, descriptor->ProductIdOffset),
        IdentityStrength::Weak, true, diskLabel + L"/product");
    collector.Add(L"storage", diskLabel + L" StorageDeviceProperty", L"product revision",
        AnsiField(output.data(), bounded, descriptor->ProductRevisionOffset),
        IdentityStrength::Weak, true, diskLabel + L"/firmware");
    SecureZeroMemory(output.data(), output.size());
}

void CollectStorageIdentifiers(
    IdentityCollector& collector,
    HANDLE disk,
    const std::wstring& diskLabel)
{
    auto output = QueryStorage(disk, StorageDeviceIdProperty);
    if (output.size() < offsetof(STORAGE_DEVICE_ID_DESCRIPTOR, Identifiers))
    {
        if (!output.empty()) SecureZeroMemory(output.data(), output.size());
        return;
    }
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_ID_DESCRIPTOR*>(output.data());
    const size_t size = descriptor->Size >= offsetof(STORAGE_DEVICE_ID_DESCRIPTOR, Identifiers)
        ? std::min<size_t>(descriptor->Size, output.size())
        : output.size();
    size_t offset = offsetof(STORAGE_DEVICE_ID_DESCRIPTOR, Identifiers);
    const ULONG count = std::min<ULONG>(descriptor->NumberOfIdentifiers, 256);
    for (ULONG index = 0; index < count; ++index)
    {
        if (offset + offsetof(STORAGE_IDENTIFIER, Identifier) > size) break;
        const auto* identifier = reinterpret_cast<const STORAGE_IDENTIFIER*>(output.data() + offset);
        const size_t base = offsetof(STORAGE_IDENTIFIER, Identifier);
        if (identifier->IdentifierSize == 0 ||
            identifier->IdentifierSize > size - offset - base) break;
        const bool uniqueType = identifier->Type == StorageIdTypeVendorId ||
            identifier->Type == StorageIdTypeEUI64 ||
            identifier->Type == StorageIdTypeFCPHName ||
            identifier->Type == StorageIdTypeScsiNameString ||
            identifier->Type == StorageIdTypeMD5LogicalUnitIdentifier;
        const std::wstring suffix = L"/id/" + std::to_wstring(identifier->Type) + L"/" +
            std::to_wstring(identifier->Association) + L"/" + std::to_wstring(index);
        collector.AddBinary(L"storage", diskLabel + L" StorageDeviceIdProperty",
            L"device identifier " + std::to_wstring(index),
            std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(identifier->Identifier),
                identifier->IdentifierSize),
            uniqueType ? IdentityStrength::Strong : IdentityStrength::Medium,
            true, diskLabel + suffix);
        if (identifier->NextOffset == 0) break;
        if (identifier->NextOffset < base + identifier->IdentifierSize ||
            identifier->NextOffset > size - offset) break;
        offset += identifier->NextOffset;
    }
    SecureZeroMemory(output.data(), output.size());
}

#pragma pack(push, 1)
struct StorageDuidHeader
{
    ULONG version;
    ULONG size;
    ULONG storageDeviceIdOffset;
    ULONG storageDeviceOffset;
    ULONG driveLayoutSignatureOffset;
};
#pragma pack(pop)

void CollectStorageDuid(IdentityCollector& collector, HANDLE disk, const std::wstring& diskLabel)
{
    auto output = QueryStorage(disk, StorageDeviceUniqueIdProperty, 1);
    if (output.size() < sizeof(StorageDuidHeader))
    {
        if (!output.empty()) SecureZeroMemory(output.data(), output.size());
        return;
    }
    const auto* duid = reinterpret_cast<const StorageDuidHeader*>(output.data());
    if (duid->version != 1 || duid->size < sizeof(StorageDuidHeader) || duid->size > output.size())
    {
        SecureZeroMemory(output.data(), output.size());
        return;
    }
    collector.AddBinary(L"storage", diskLabel + L" StorageDeviceUniqueIdProperty",
        L"storage DUID", std::span<const std::byte>(output.data(), duid->size),
        IdentityStrength::Strong, true, diskLabel + L"/duid");
    SecureZeroMemory(output.data(), output.size());
}

void CollectStorageAdapterAndFru(
    IdentityCollector& collector,
    HANDLE disk,
    const std::wstring& diskLabel)
{
    auto output = QueryStorage(disk, StorageAdapterSerialNumberProperty);
    if (output.size() >= sizeof(STORAGE_ADAPTER_SERIAL_NUMBER))
    {
        const auto* serial = reinterpret_cast<const STORAGE_ADAPTER_SERIAL_NUMBER*>(output.data());
        const size_t capacity = std::min<size_t>(STORAGE_ADAPTER_SERIAL_NUMBER_V1_MAX_LENGTH,
            (output.size() - offsetof(STORAGE_ADAPTER_SERIAL_NUMBER, SerialNumber)) / sizeof(wchar_t));
        collector.Add(L"storage", diskLabel + L" StorageAdapterSerialNumberProperty",
            L"adapter serial", std::wstring(serial->SerialNumber,
                wcsnlen_s(serial->SerialNumber, capacity)), IdentityStrength::Strong, true,
            diskLabel + L"/adapter-serial", true);
    }

    if (!output.empty()) SecureZeroMemory(output.data(), output.size());
    output = QueryStorage(disk, StorageFruIdProperty);
    if (output.size() >= offsetof(STORAGE_FRU_ID_DESCRIPTOR, Identifier))
    {
        const auto* fru = reinterpret_cast<const STORAGE_FRU_ID_DESCRIPTOR*>(output.data());
        const size_t base = offsetof(STORAGE_FRU_ID_DESCRIPTOR, Identifier);
        const size_t bounded = fru->Size >= base ? std::min<size_t>(fru->Size, output.size()) : output.size();
        if (fru->IdentifierSize != 0 && fru->IdentifierSize <= bounded - base)
            collector.AddBinary(L"storage", diskLabel + L" StorageFruIdProperty", L"FRU identifier",
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(fru->Identifier), fru->IdentifierSize),
                IdentityStrength::Strong, true, diskLabel + L"/fru-id");
    }
    if (!output.empty()) SecureZeroMemory(output.data(), output.size());
}

std::vector<std::byte> QueryNvmeIdentify(
    HANDLE disk,
    STORAGE_PROPERTY_ID property,
    ULONG requestValue)
{
    const size_t inputSize = offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters) +
        sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    std::vector<std::byte> input(inputSize);
    auto* query = reinterpret_cast<STORAGE_PROPERTY_QUERY*>(input.data());
    query->PropertyId = property;
    query->QueryType = PropertyStandardQuery;
    auto* protocol = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(query->AdditionalParameters);
    protocol->ProtocolType = ProtocolTypeNvme;
    protocol->DataType = NVMeDataTypeIdentify;
    protocol->ProtocolDataRequestValue = requestValue;
    protocol->ProtocolDataRequestSubValue = 0;
    protocol->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    protocol->ProtocolDataLength = 4096;

    std::vector<std::byte> output(sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) + 4096);
    DWORD returned = 0;
    if (!DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY,
            input.data(), static_cast<DWORD>(input.size()), output.data(),
            static_cast<DWORD>(output.size()), &returned, nullptr) ||
        returned < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) || returned > output.size())
    {
        SecureZeroMemory(output.data(), output.size());
        return {};
    }
    output.resize(returned);
    const auto* descriptor = reinterpret_cast<const STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(output.data());
    const auto& result = descriptor->ProtocolSpecificData;
    const size_t base = offsetof(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData);
    if (result.ProtocolType != ProtocolTypeNvme || result.DataType != NVMeDataTypeIdentify ||
        result.ProtocolDataLength < 4096 || result.ProtocolDataOffset > output.size() - base ||
        result.ProtocolDataLength > output.size() - base - result.ProtocolDataOffset)
    {
        SecureZeroMemory(output.data(), output.size());
        return {};
    }
    const std::byte* data = output.data() + base + result.ProtocolDataOffset;
    std::vector<std::byte> identity(data, data + result.ProtocolDataLength);
    SecureZeroMemory(output.data(), output.size());
    return identity;
}

void CollectNvmeIdentity(IdentityCollector& collector, HANDLE disk, const std::wstring& diskLabel)
{
    auto data = QueryNvmeIdentify(disk, StorageAdapterProtocolSpecificProperty,
        NVME_IDENTIFY_CNS_CONTROLLER);
    if (data.size() >= sizeof(NVME_IDENTIFY_CONTROLLER_DATA))
    {
        const auto* identify = reinterpret_cast<const NVME_IDENTIFY_CONTROLLER_DATA*>(data.data());
        collector.Add(L"storage", diskLabel + L" NVMe Identify Controller", L"NVMe serial",
            FixedAnsi(identify->SN, sizeof(identify->SN)), IdentityStrength::Strong, true,
            diskLabel + L"/controller-serial", true);
        collector.Add(L"storage", diskLabel + L" NVMe Identify Controller", L"NVMe model",
            FixedAnsi(identify->MN, sizeof(identify->MN)), IdentityStrength::Weak, true,
            diskLabel + L"/product");
        collector.Add(L"storage", diskLabel + L" NVMe Identify Controller", L"NVMe firmware",
            FixedAnsi(identify->FR, sizeof(identify->FR)), IdentityStrength::Weak, true,
            diskLabel + L"/firmware");
        collector.AddBinary(L"storage", diskLabel + L" NVMe Identify Controller", L"NVMe FRU GUID",
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(identify->FGUID),
                sizeof(identify->FGUID)), IdentityStrength::Strong, true, diskLabel + L"/nvme-fru-guid");
        collector.AddBinary(L"storage", diskLabel + L" NVMe Identify Controller", L"NVMe IEEE OUI",
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(identify->IEEE),
                sizeof(identify->IEEE)), IdentityStrength::Weak, true, diskLabel + L"/nvme-oui");
    }
    if (!data.empty()) SecureZeroMemory(data.data(), data.size());

    data = QueryNvmeIdentify(disk, StorageDeviceProtocolSpecificProperty,
        NVME_IDENTIFY_CNS_SPECIFIC_NAMESPACE);
    if (data.size() >= sizeof(NVME_IDENTIFY_NAMESPACE_DATA))
    {
        const auto* identify = reinterpret_cast<const NVME_IDENTIFY_NAMESPACE_DATA*>(data.data());
        collector.AddBinary(L"storage", diskLabel + L" NVMe Identify Namespace", L"namespace NGUID",
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(identify->NGUID),
                sizeof(identify->NGUID)), IdentityStrength::Strong, true, diskLabel + L"/nvme-nguid");
        collector.AddBinary(L"storage", diskLabel + L" NVMe Identify Namespace", L"namespace EUI64",
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(identify->EUI64),
                sizeof(identify->EUI64)), IdentityStrength::Strong, true, diskLabel + L"/nvme-eui64");
    }
    if (!data.empty()) SecureZeroMemory(data.data(), data.size());
}

std::wstring AtaWordString(const BYTE* data, size_t offset, size_t length)
{
    std::wstring result;
    result.reserve(length);
    for (size_t index = 0; index + 1 < length; index += 2)
    {
        result.push_back(static_cast<unsigned char>(data[offset + index + 1]));
        result.push_back(static_cast<unsigned char>(data[offset + index]));
    }
    return TrimAndNormalize(result);
}

void CollectAtaIdentify(
    IdentityCollector& collector,
    unsigned diskIndex,
    const std::wstring& path,
    const std::wstring& diskLabel)
{
    UniqueHandle disk(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!disk || diskIndex > std::numeric_limits<BYTE>::max()) return;
    GETVERSIONINPARAMS version{};
    DWORD returned = 0;
    if (!DeviceIoControl(disk.get(), SMART_GET_VERSION, nullptr, 0,
            &version, sizeof(version), &returned, nullptr)) return;

    SENDCMDINPARAMS input{};
    input.cBufferSize = 512;
    input.irDriveRegs.bSectorCountReg = 1;
    input.irDriveRegs.bSectorNumberReg = 1;
    input.irDriveRegs.bDriveHeadReg = static_cast<BYTE>(0xA0 | ((diskIndex & 1U) << 4));
    input.irDriveRegs.bCommandReg = 0xEC;
    input.bDriveNumber = static_cast<BYTE>(diskIndex);
    std::vector<std::byte> output(sizeof(SENDCMDOUTPARAMS) + 511);
    if (!DeviceIoControl(disk.get(), SMART_RCV_DRIVE_DATA,
            &input, sizeof(SENDCMDINPARAMS) - 1, output.data(), static_cast<DWORD>(output.size()),
            &returned, nullptr) || returned < offsetof(SENDCMDOUTPARAMS, bBuffer) + 512)
        return;
    const auto* identify = reinterpret_cast<const SENDCMDOUTPARAMS*>(output.data())->bBuffer;
    collector.Add(L"storage", diskLabel + L" ATA IDENTIFY", L"ATA serial",
        AtaWordString(identify, 20, 20), IdentityStrength::Strong, true,
        diskLabel + L"/controller-serial", true);
    collector.Add(L"storage", diskLabel + L" ATA IDENTIFY", L"ATA firmware",
        AtaWordString(identify, 46, 8), IdentityStrength::Weak, true,
        diskLabel + L"/firmware");
    collector.Add(L"storage", diskLabel + L" ATA IDENTIFY", L"ATA model",
        AtaWordString(identify, 54, 40), IdentityStrength::Weak, true,
        diskLabel + L"/product");
    SecureZeroMemory(output.data(), output.size());
}

void CollectDriveLayout(IdentityCollector& collector, HANDLE disk, const std::wstring& diskLabel)
{
    std::vector<std::byte> output(size_t{128} * 1024);
    DWORD returned = 0;
    if (!DeviceIoControl(disk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0,
            output.data(), static_cast<DWORD>(output.size()), &returned, nullptr) ||
        returned < offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) || returned > output.size())
        return;
    const auto* layout = reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(output.data());
    if (layout->PartitionStyle == PARTITION_STYLE_GPT && !IsZeroGuid(layout->Gpt.DiskId))
        collector.Add(L"storage", diskLabel + L" drive layout", L"GPT disk GUID",
            GuidText(layout->Gpt.DiskId), IdentityStrength::Strong, true, diskLabel + L"/gpt-disk-id");
    else if (layout->PartitionStyle == PARTITION_STYLE_MBR && layout->Mbr.Signature != 0)
        collector.Add(L"storage", diskLabel + L" drive layout", L"MBR signature",
            std::to_wstring(layout->Mbr.Signature), IdentityStrength::Medium, true,
            diskLabel + L"/mbr-signature");

    const size_t maximum = (returned - offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) /
        sizeof(PARTITION_INFORMATION_EX);
    const size_t count = std::min<size_t>({layout->PartitionCount, maximum, 256});
    for (size_t index = 0; index < count; ++index)
    {
        const auto& partition = layout->PartitionEntry[index];
        if (partition.PartitionStyle == PARTITION_STYLE_GPT && !IsZeroGuid(partition.Gpt.PartitionId))
            collector.Add(L"storage", diskLabel + L" drive layout", L"GPT partition GUID " +
                std::to_wstring(index), GuidText(partition.Gpt.PartitionId),
                IdentityStrength::Medium, true,
                diskLabel + L"/partition/" + std::to_wstring(index) + L"/gpt-id");
    }
    SecureZeroMemory(output.data(), output.size());
}

std::set<DWORD> SystemDiskNumbers()
{
    std::set<DWORD> result;
    std::array<wchar_t, MAX_PATH> systemDirectory{};
    if (GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size())) == 0 ||
        systemDirectory[1] != L':') return result;
    const wchar_t volumePath[] = {L'\\', L'\\', L'.', L'\\', systemDirectory[0], L':', L'\0'};
    UniqueHandle volume(CreateFileW(volumePath, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    if (!volume) return result;
    std::vector<std::byte> output(size_t{64} * 1024);
    DWORD returned = 0;
    if (!DeviceIoControl(volume.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
            output.data(), static_cast<DWORD>(output.size()), &returned, nullptr) ||
        returned < offsetof(VOLUME_DISK_EXTENTS, Extents) || returned > output.size())
        return result;
    const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(output.data());
    const size_t maximum = (returned - offsetof(VOLUME_DISK_EXTENTS, Extents)) / sizeof(DISK_EXTENT);
    const size_t count = std::min<size_t>(extents->NumberOfDiskExtents, maximum);
    for (size_t index = 0; index < count; ++index) result.insert(extents->Extents[index].DiskNumber);
    SecureZeroMemory(output.data(), output.size());
    return result;
}

void CollectPhysicalStorage(IdentityCollector& collector, Reporter& reporter)
{
    const std::set<DWORD> systemDisks = SystemDiskNumbers();
    size_t disks = 0;
    for (unsigned index = 0; index < 64; ++index)
    {
        const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(index);
        UniqueHandle disk(CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        if (!disk)
        {
            continue;
        }
        ++disks;
        const std::wstring label = L"disk" + std::to_wstring(index);
        CollectStorageDeviceDescriptor(collector, disk.get(), label);
        CollectStorageIdentifiers(collector, disk.get(), label);
        CollectStorageDuid(collector, disk.get(), label);
        CollectStorageAdapterAndFru(collector, disk.get(), label);
        CollectNvmeIdentity(collector, disk.get(), label);
        CollectDriveLayout(collector, disk.get(), label);
        CollectAtaIdentify(collector, index, path, label);
        if (!systemDisks.empty() && !systemDisks.contains(index))
            collector.MarkPeripheralGroupPrefix(label + L"/");
    }
    reporter.Add(disks == 0 ? FindingSeverity::Medium : FindingSeverity::Info, L"hwid/storage",
        L"Queried " + std::to_wstring(disks) +
        L" physical disks through descriptor, ID, DUID, FRU, layout, NVMe, and ATA read-only paths; " +
        std::to_wstring(systemDisks.size()) + L" system-volume backing disks are core anchors");
}

#pragma pack(push, 1)
struct MountdevUniqueId
{
    USHORT length;
    BYTE value[1];
};

struct MountdevStableGuid
{
    GUID guid;
};
#pragma pack(pop)

void CollectVolumes(IdentityCollector& collector, Reporter& reporter)
{
    std::array<wchar_t, MAX_PATH> systemDirectory{};
    std::array<wchar_t, 1024> systemVolume{};
    if (GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size())) != 0 &&
        systemDirectory[1] == L':')
    {
        const wchar_t root[] = {systemDirectory[0], L':', L'\\', L'\0'};
        (void)GetVolumeNameForVolumeMountPointW(root, systemVolume.data(),
            static_cast<DWORD>(systemVolume.size()));
    }
    std::array<wchar_t, 1024> name{};
    HANDLE find = FindFirstVolumeW(name.data(), static_cast<DWORD>(name.size()));
    if (find == INVALID_HANDLE_VALUE)
    {
        reporter.Add(FindingSeverity::Low, L"hwid/volumes", L"Volume enumeration is unavailable");
        return;
    }
    size_t count = 0;
    for (;;)
    {
        std::wstring volume(name.data());
        const std::wstring label = L"volume" + std::to_wstring(count);
        collector.Add(L"volume", L"FindFirstVolume", L"volume GUID " + std::to_wstring(count),
            volume, IdentityStrength::Medium, true, label + L"/volume-guid");
        DWORD serial = 0;
        if (GetVolumeInformationW(volume.c_str(), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0) &&
            serial != 0)
            collector.Add(L"volume", L"GetVolumeInformation", L"filesystem serial " +
                std::to_wstring(count), std::to_wstring(serial), IdentityStrength::Weak, true,
                label + L"/filesystem-serial");

        if (volume.ends_with(L"\\")) volume.pop_back();
        UniqueHandle handle(CreateFileW(volume.c_str(), 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        if (handle)
        {
            std::vector<std::byte> output(size_t{64} * 1024);
            DWORD returned = 0;
            if (DeviceIoControl(handle.get(), kIoctlMountdevQueryUniqueId, nullptr, 0,
                    output.data(), static_cast<DWORD>(output.size()), &returned, nullptr) &&
                returned >= offsetof(MountdevUniqueId, value))
            {
                const auto* unique = reinterpret_cast<const MountdevUniqueId*>(output.data());
                if (unique->length != 0 &&
                    unique->length <= returned - offsetof(MountdevUniqueId, value))
                    collector.AddBinary(L"volume", L"mountmgr unique ID",
                        L"mount-manager unique ID " + std::to_wstring(count),
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte*>(unique->value), unique->length),
                        IdentityStrength::Strong, true, label + L"/mountdev-unique-id");
            }
            MountdevStableGuid stable{};
            returned = 0;
            if (DeviceIoControl(handle.get(), kIoctlMountdevQueryStableGuid, nullptr, 0,
                    &stable, sizeof(stable), &returned, nullptr) && returned >= sizeof(stable) &&
                !IsZeroGuid(stable.guid))
                collector.Add(L"volume", L"mountmgr stable GUID",
                    L"mount-manager stable GUID " + std::to_wstring(count), GuidText(stable.guid),
                    IdentityStrength::Strong, true, label + L"/mountdev-stable-guid");
            SecureZeroMemory(output.data(), output.size());
        }
        const bool isSystemVolume = systemVolume[0] != L'\0' &&
            _wcsicmp(name.data(), systemVolume.data()) == 0;
        if (systemVolume[0] != L'\0' && !isSystemVolume)
            collector.MarkPeripheralGroupPrefix(label + L"/");
        Wipe(volume);
        ++count;
        if (!FindNextVolumeW(find, name.data(), static_cast<DWORD>(name.size()))) break;
    }
    FindVolumeClose(find);
    SecureZeroMemory(name.data(), name.size() * sizeof(wchar_t));
    SecureZeroMemory(systemVolume.data(), systemVolume.size() * sizeof(wchar_t));
    reporter.Add(FindingSeverity::Info, L"hwid/volumes",
        L"Queried " + std::to_wstring(count) + L" volumes through volume and mount-manager identities");
}

std::wstring DeviceInstanceId(HDEVINFO set, SP_DEVINFO_DATA& device)
{
    DWORD required = 0;
    (void)SetupDiGetDeviceInstanceIdW(set, &device, nullptr, 0, &required);
    if (required == 0 || required > 32768) return {};
    std::vector<wchar_t> buffer(required + 1);
    if (!SetupDiGetDeviceInstanceIdW(set, &device, buffer.data(),
            static_cast<DWORD>(buffer.size()), nullptr)) return {};
    return buffer.data();
}

std::vector<std::byte> DeviceProperty(
    HDEVINFO set,
    SP_DEVINFO_DATA& device,
    const DEVPROPKEY& key,
    DEVPROPTYPE& type)
{
    type = DEVPROP_TYPE_EMPTY;
    DWORD required = 0;
    (void)SetupDiGetDevicePropertyW(set, &device, &key, &type, nullptr, 0, &required, 0);
    if (required == 0 || required > 1024 * 1024) return {};
    std::vector<std::byte> value(required);
    if (!SetupDiGetDevicePropertyW(set, &device, &key, &type,
            reinterpret_cast<PBYTE>(value.data()), required, nullptr, 0)) return {};
    return value;
}

bool IdentityRelevantClass(const GUID& guid)
{
    return IsEqualGUID(guid, GUID_DEVCLASS_DISKDRIVE) ||
        IsEqualGUID(guid, GUID_DEVCLASS_NET) ||
        IsEqualGUID(guid, GUID_DEVCLASS_DISPLAY) ||
        IsEqualGUID(guid, GUID_DEVCLASS_MONITOR) ||
        IsEqualGUID(guid, GUID_DEVCLASS_USB) ||
        IsEqualGUID(guid, GUID_DEVCLASS_BLUETOOTH) ||
        IsEqualGUID(guid, GUID_DEVCLASS_HIDCLASS) ||
        IsEqualGUID(guid, GUID_DEVCLASS_BATTERY) ||
        IsEqualGUID(guid, GUID_DEVCLASS_PROCESSOR) ||
        IsEqualGUID(guid, GUID_DEVCLASS_MEMORY);
}

void CollectPnpIdentity(IdentityCollector& collector, Reporter& reporter)
{
    UniqueDevInfo set(SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT));
    if (!set)
    {
        reporter.Add(FindingSeverity::Medium, L"hwid/pnp", L"PnP identity enumeration failed");
        return;
    }
    size_t relevant = 0;
    for (DWORD index = 0;; ++index)
    {
        SP_DEVINFO_DATA device{};
        device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(set.get(), index, &device)) break;
        if (!IdentityRelevantClass(device.ClassGuid)) continue;
        std::wstring instance = DeviceInstanceId(set.get(), device);
        if (instance.empty()) continue;
        const std::wstring label = L"pnp" + std::to_wstring(relevant++);
        const bool software = instance.starts_with(L"ROOT\\") || instance.starts_with(L"SWD\\");
        const bool peripheralClass = IsEqualGUID(device.ClassGuid, GUID_DEVCLASS_HIDCLASS) ||
            IsEqualGUID(device.ClassGuid, GUID_DEVCLASS_BLUETOOTH) ||
            IsEqualGUID(device.ClassGuid, GUID_DEVCLASS_BATTERY) ||
            IsEqualGUID(device.ClassGuid, GUID_DEVCLASS_DISKDRIVE) ||
            IsEqualGUID(device.ClassGuid, GUID_DEVCLASS_MONITOR) ||
            IsEqualGUID(device.ClassGuid, GUID_DEVCLASS_USB);
        collector.Add(L"pnp", L"SetupAPI", L"device instance " + std::to_wstring(index), instance,
            (software || peripheralClass) ? IdentityStrength::Weak : IdentityStrength::Medium,
            !software && !peripheralClass, label + L"/instance-id", false, peripheralClass);

        DEVPROPTYPE type = DEVPROP_TYPE_EMPTY;
        auto value = DeviceProperty(set.get(), device, kDeviceContainerId, type);
        if (type == DEVPROP_TYPE_GUID && value.size() >= sizeof(GUID))
        {
            GUID guid{};
            memcpy(&guid, value.data(), sizeof(guid));
            if (!IsZeroGuid(guid))
                collector.Add(L"pnp", L"SetupAPI container", L"container ID " + std::to_wstring(index),
                    GuidText(guid), peripheralClass ? IdentityStrength::Weak : IdentityStrength::Medium,
                    !software && !peripheralClass, label + L"/container-id", false, peripheralClass);
        }
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
        Wipe(instance);
        value = DeviceProperty(set.get(), device, kDeviceBaseContainerId, type);
        if (type == DEVPROP_TYPE_GUID && value.size() >= sizeof(GUID))
        {
            GUID guid{};
            memcpy(&guid, value.data(), sizeof(guid));
            if (!IsZeroGuid(guid))
                collector.Add(L"pnp", L"SetupAPI base container", L"base container ID " +
                    std::to_wstring(index), GuidText(guid),
                    peripheralClass ? IdentityStrength::Weak : IdentityStrength::Medium,
                    !software && !peripheralClass, label + L"/base-container-id", false, peripheralClass);
        }
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
        value = DeviceProperty(set.get(), device, kDeviceExtendedAddress, type);
        if (type == DEVPROP_TYPE_UINT64 && value.size() >= sizeof(ULONGLONG))
        {
            ULONGLONG address = 0;
            memcpy(&address, value.data(), sizeof(address));
            if (address != 0)
                collector.Add(L"pnp", L"SetupAPI extended address", L"extended address " +
                    std::to_wstring(index), std::to_wstring(address), IdentityStrength::Medium,
                    !software && !peripheralClass, label + L"/extended-address", false, peripheralClass);
        }
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
        value = DeviceProperty(set.get(), device, kDeviceLocationPaths, type);
        if ((type & DEVPROP_MASK_TYPE) == DEVPROP_TYPE_STRING_LIST &&
            value.size() >= sizeof(wchar_t) &&
            (value.size() % sizeof(wchar_t)) == 0)
        {
            const size_t capacity = value.size() / sizeof(wchar_t);
            std::vector<wchar_t> paths(capacity + 1);
            memcpy(paths.data(), value.data(), value.size());
            collector.Add(L"pnp", L"SetupAPI location", L"location path " + std::to_wstring(index),
                std::wstring(paths.data(), wcsnlen_s(paths.data(), capacity)), IdentityStrength::Weak,
                !software && !peripheralClass, label + L"/location", false, peripheralClass);
            SecureZeroMemory(paths.data(), paths.size() * sizeof(wchar_t));
        }
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    }
    reporter.Add(FindingSeverity::Info, L"hwid/pnp",
        L"Collected bounded identity properties from " + std::to_wstring(relevant) +
        L" identity-relevant present PnP devices");
}

std::wstring MacText(const UCHAR* address, ULONG length)
{
    if (length == 0 || length > IF_MAX_PHYS_ADDRESS_LENGTH) return {};
    return BytesToHex(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(address), length));
}

bool ZeroAddress(const UCHAR* address, ULONG length)
{
    return length == 0 || std::all_of(address, address + length,
        [](UCHAR value) { return value == 0; });
}

void CollectNetworkIdentity(IdentityCollector& collector, Reporter& reporter)
{
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR || table == nullptr)
    {
        reporter.Add(FindingSeverity::Low, L"hwid/network", L"Network interface identity query failed");
        return;
    }
    size_t linkLayer = 0;
    size_t hardware = 0;
    size_t mismatches = 0;
    for (ULONG index = 0; index < table->NumEntries; ++index)
    {
        const auto& row = table->Table[index];
        if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK || row.Type == IF_TYPE_TUNNEL ||
            row.PhysicalAddressLength == 0 || row.PhysicalAddressLength > IF_MAX_PHYS_ADDRESS_LENGTH)
            continue;
        const bool hardwareInterface = row.InterfaceAndOperStatusFlags.HardwareInterface != FALSE;
        if (hardwareInterface) ++hardware;
        const std::wstring label = L"network" + std::to_wstring(linkLayer++);
        collector.Add(L"network", L"MIB_IF_ROW2", L"interface GUID " + std::to_wstring(index),
            GuidText(row.InterfaceGuid),
            hardwareInterface ? IdentityStrength::Medium : IdentityStrength::Weak,
            hardwareInterface, label + L"/interface-guid");
        if (!ZeroAddress(row.PermanentPhysicalAddress, row.PhysicalAddressLength))
            collector.Add(L"network", L"MIB_IF_ROW2 permanent", L"permanent MAC " +
                std::to_wstring(index), MacText(row.PermanentPhysicalAddress, row.PhysicalAddressLength),
                hardwareInterface ? IdentityStrength::Strong : IdentityStrength::Weak,
                hardwareInterface, label + L"/permanent-mac", true);
        if (!ZeroAddress(row.PhysicalAddress, row.PhysicalAddressLength))
            collector.Add(L"network", L"MIB_IF_ROW2 current", L"current MAC " +
                std::to_wstring(index), MacText(row.PhysicalAddress, row.PhysicalAddressLength),
                hardwareInterface ? IdentityStrength::Medium : IdentityStrength::Weak,
                hardwareInterface, label + L"/current-mac");
        if (hardwareInterface &&
            !ZeroAddress(row.PermanentPhysicalAddress, row.PhysicalAddressLength) &&
            !ZeroAddress(row.PhysicalAddress, row.PhysicalAddressLength) &&
            memcmp(row.PermanentPhysicalAddress, row.PhysicalAddress,
                row.PhysicalAddressLength) != 0)
            ++mismatches;
    }
    if (table->NumEntries <= 100000)
    {
        const size_t bytes = offsetof(MIB_IF_TABLE2, Table) +
            static_cast<size_t>(table->NumEntries) * sizeof(MIB_IF_ROW2);
        SecureZeroMemory(table, bytes);
    }
    FreeMibTable(table);
    reporter.Add(mismatches == 0 ? FindingSeverity::Info : FindingSeverity::Low,
        L"hwid/network", L"Queried " + std::to_wstring(linkLayer) +
        L" link-layer interfaces (hardware=" + std::to_wstring(hardware) +
        L"); hardware current/permanent MAC mismatches=" +
        std::to_wstring(mismatches) + L" (randomization or administrative override may be legitimate)");
}

std::vector<std::byte> RegistryBinary(HKEY root, const std::wstring& path, const wchar_t* name)
{
    DWORD type = REG_NONE;
    auto value = RegistryValue(root, path.c_str(), name, type);
    if (type != REG_BINARY)
    {
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
        value.clear();
    }
    return value;
}

void CollectMonitorEdid(IdentityCollector& collector, Reporter& reporter)
{
    HKEY rawDisplay = nullptr;
    constexpr wchar_t displayPath[] = L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, displayPath, 0, KEY_ENUMERATE_SUB_KEYS, &rawDisplay) != ERROR_SUCCESS)
        return;
    UniqueRegKey display(rawDisplay);
    size_t monitors = 0;
    size_t overrides = 0;
    std::array<wchar_t, 512> firstName{};
    for (DWORD first = 0;; ++first)
    {
        DWORD firstLength = static_cast<DWORD>(firstName.size());
        if (RegEnumKeyExW(display.get(), first, firstName.data(), &firstLength,
                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        const std::wstring firstPath = std::wstring(displayPath) + L"\\" + firstName.data();
        HKEY rawModel = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, firstPath.c_str(), 0,
                KEY_ENUMERATE_SUB_KEYS, &rawModel) != ERROR_SUCCESS) continue;
        UniqueRegKey model(rawModel);
        std::array<wchar_t, 512> secondName{};
        for (DWORD second = 0;; ++second)
        {
            DWORD secondLength = static_cast<DWORD>(secondName.size());
            if (RegEnumKeyExW(model.get(), second, secondName.data(), &secondLength,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            const std::wstring base = firstPath + L"\\" + secondName.data();
            auto edid = RegistryBinary(HKEY_LOCAL_MACHINE, base + L"\\Device Parameters", L"EDID");
            if (edid.size() < 128) continue;
            const std::wstring label = L"monitor" + std::to_wstring(monitors++);
            collector.AddDigest(L"monitor", L"EDID", L"EDID digest", edid,
                IdentityStrength::Medium, true, label + L"/edid-digest");
            const auto* bytes = reinterpret_cast<const BYTE*>(edid.data());
            const DWORD numericSerial = static_cast<DWORD>(bytes[12]) |
                (static_cast<DWORD>(bytes[13]) << 8) |
                (static_cast<DWORD>(bytes[14]) << 16) |
                (static_cast<DWORD>(bytes[15]) << 24);
            if (numericSerial != 0 && numericSerial != 0xFFFFFFFF)
                collector.Add(L"monitor", L"EDID numeric", L"numeric monitor serial",
                    std::to_wstring(numericSerial), IdentityStrength::Strong, true,
                    label + L"/numeric-serial");
            const WORD product = static_cast<WORD>(bytes[10] | (bytes[11] << 8));
            collector.Add(L"monitor", L"EDID product", L"monitor product code",
                std::to_wstring(product), IdentityStrength::Weak, true, label + L"/product");
            for (size_t descriptor = 54; descriptor + 18 <= 126; descriptor += 18)
            {
                if (bytes[descriptor] == 0 && bytes[descriptor + 1] == 0 &&
                    bytes[descriptor + 2] == 0 && bytes[descriptor + 3] == 0xFF)
                {
                    std::wstring serial;
                    for (size_t offset = descriptor + 5; offset < descriptor + 18; ++offset)
                    {
                        if (bytes[offset] == 0x0A || bytes[offset] == 0x00) break;
                        serial.push_back(bytes[offset]);
                    }
                    collector.Add(L"monitor", L"EDID descriptor", L"text monitor serial", serial,
                        IdentityStrength::Strong, true, label + L"/text-serial");
                }
            }
            collector.MarkPeripheralGroupPrefix(label + L"/");
            HKEY overrideKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    (base + L"\\Device Parameters\\EDID_OVERRIDE").c_str(), 0,
                    KEY_QUERY_VALUE, &overrideKey) == ERROR_SUCCESS)
            {
                ++overrides;
                RegCloseKey(overrideKey);
            }
            SecureZeroMemory(edid.data(), edid.size());
        }
    }
    reporter.Add(overrides == 0 ? FindingSeverity::Info : FindingSeverity::Medium,
        L"hwid/monitor", L"Parsed " + std::to_wstring(monitors) +
        L" monitor EDID records; EDID override keys=" + std::to_wstring(overrides));
}

void CollectHidSerials(IdentityCollector& collector, Reporter& reporter)
{
    GUID hidGuid{};
    HidD_GetHidGuid(&hidGuid);
    UniqueDevInfo set(SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT));
    if (!set) return;
    size_t serials = 0;
    for (DWORD index = 0; index < 512; ++index)
    {
        SP_DEVICE_INTERFACE_DATA interfaceData{};
        interfaceData.cbSize = sizeof(interfaceData);
        if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &hidGuid, index, &interfaceData)) break;
        DWORD required = 0;
        (void)SetupDiGetDeviceInterfaceDetailW(set.get(), &interfaceData, nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) || required > 64 * 1024) continue;
        std::vector<std::byte> detailBuffer(required);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detailBuffer.data());
        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interfaceData, detail, required,
                nullptr, nullptr)) continue;
        UniqueHandle device(CreateFileW(detail->DevicePath, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!device) continue;
        std::array<wchar_t, 256> serial{};
        if (!HidD_GetSerialNumberString(device.get(), serial.data(),
                static_cast<ULONG>(serial.size() * sizeof(wchar_t)))) continue;
        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(attributes);
        (void)HidD_GetAttributes(device.get(), &attributes);
        const std::wstring label = L"hid/" + std::to_wstring(attributes.VendorID) + L"/" +
            std::to_wstring(attributes.ProductID) + L"/" + std::to_wstring(index);
        collector.Add(L"peripheral", L"HID API", L"HID serial", serial.data(),
            IdentityStrength::Weak, true, label + L"/serial", false, true);
        SecureZeroMemory(serial.data(), serial.size() * sizeof(wchar_t));
        ++serials;
    }
    reporter.Add(FindingSeverity::Info, L"hwid/peripheral",
        L"Collected " + std::to_wstring(serials) +
        L" optional HID serials as weak peripheral-only evidence");
}

std::wstring QueryBatteryString(
    HANDLE battery,
    ULONG tag,
    BATTERY_QUERY_INFORMATION_LEVEL level)
{
    BATTERY_QUERY_INFORMATION query{};
    query.BatteryTag = tag;
    query.InformationLevel = level;
    std::vector<wchar_t> output(1024);
    DWORD returned = 0;
    if (!DeviceIoControl(battery, IOCTL_BATTERY_QUERY_INFORMATION,
            &query, sizeof(query), output.data(),
            static_cast<DWORD>(output.size() * sizeof(wchar_t)),
            &returned, nullptr) || returned < sizeof(wchar_t) ||
        returned > output.size() * sizeof(wchar_t) ||
        (returned & (sizeof(wchar_t) - 1)) != 0)
    {
        SecureZeroMemory(output.data(), output.size() * sizeof(wchar_t));
        return {};
    }
    const size_t characters = returned / sizeof(wchar_t);
    std::wstring value(output.data(), wcsnlen_s(output.data(), characters));
    SecureZeroMemory(output.data(), output.size() * sizeof(wchar_t));
    return value;
}

void CollectBatteryIdentity(IdentityCollector& collector, Reporter& reporter)
{
    UniqueDevInfo set(SetupDiGetClassDevsW(
        &kBatteryInterface,
        nullptr,
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (!set)
    {
        reporter.Add(FindingSeverity::Low, L"hwid/battery",
            L"Battery device-interface enumeration is unavailable");
        return;
    }

    size_t devices = 0;
    size_t serials = 0;
    for (DWORD index = 0; index < 64; ++index)
    {
        SP_DEVICE_INTERFACE_DATA interfaceData{};
        interfaceData.cbSize = sizeof(interfaceData);
        if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr,
                &kBatteryInterface, index, &interfaceData))
        {
            if (GetLastError() != ERROR_NO_MORE_ITEMS)
                reporter.Add(FindingSeverity::Low, L"hwid/battery",
                    L"Battery interface enumeration ended on an unexpected error");
            break;
        }

        DWORD required = 0;
        (void)SetupDiGetDeviceInterfaceDetailW(set.get(), &interfaceData,
            nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W) ||
            required > size_t{64} * 1024) continue;
        std::vector<std::byte> detailBuffer(required);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(
            detailBuffer.data());
        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interfaceData,
                detail, required, nullptr, nullptr)) continue;

        UniqueHandle battery(CreateFileW(detail->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!battery) continue;
        ++devices;
        ULONG timeout = 0;
        ULONG tag = 0;
        DWORD returned = 0;
        if (!DeviceIoControl(battery.get(), IOCTL_BATTERY_QUERY_TAG,
                &timeout, sizeof(timeout), &tag, sizeof(tag), &returned, nullptr) ||
            returned != sizeof(tag) || tag == 0) continue;

        const std::wstring label = L"battery" + std::to_wstring(index);
        auto addString = [&](BATTERY_QUERY_INFORMATION_LEVEL level,
                             const wchar_t* name,
                             IdentityStrength strength,
                             const wchar_t* group,
                             bool comparable)
        {
            std::wstring value = QueryBatteryString(battery.get(), tag, level);
            if (value.empty()) return;
            if (level == BatterySerialNumber || level == BatteryUniqueID) ++serials;
            collector.Add(L"battery", L"battery class IOCTL", name,
                std::move(value), strength, true, label + group,
                comparable, true);
        };
        addString(BatterySerialNumber, L"battery serial",
            IdentityStrength::Strong, L"/serial", true);
        addString(BatteryUniqueID, L"battery unique ID",
            IdentityStrength::Strong, L"/unique-id", true);
        addString(BatteryManufactureName, L"battery manufacturer",
            IdentityStrength::Weak, L"/manufacturer", false);
        addString(BatteryDeviceName, L"battery device name",
            IdentityStrength::Weak, L"/device-name", false);

        BATTERY_QUERY_INFORMATION dateQuery{};
        dateQuery.BatteryTag = tag;
        dateQuery.InformationLevel = BatteryManufactureDate;
        BATTERY_MANUFACTURE_DATE date{};
        returned = 0;
        if (DeviceIoControl(battery.get(), IOCTL_BATTERY_QUERY_INFORMATION,
                &dateQuery, sizeof(dateQuery), &date, sizeof(date),
                &returned, nullptr) && returned == sizeof(date) &&
            date.Year >= 1980 && date.Year <= 3000 &&
            date.Month >= 1 && date.Month <= 12 &&
            date.Day >= 1 && date.Day <= 31)
        {
            collector.Add(L"battery", L"battery class IOCTL",
                L"battery manufacture date",
                std::to_wstring(date.Year) + L"-" +
                    std::to_wstring(date.Month) + L"-" +
                    std::to_wstring(date.Day),
                IdentityStrength::Weak, true, label + L"/manufacture-date",
                false, true);
        }
    }

    reporter.Add(FindingSeverity::Info, L"hwid/battery",
        L"Queried " + std::to_wstring(devices) +
            L" battery interfaces through the documented battery class protocol; serial/unique-ID values=" +
            std::to_wstring(serials) + L" (peripheral-only evidence)");
}

void CollectBluetoothRadios(IdentityCollector& collector, Reporter& reporter)
{
    BLUETOOTH_FIND_RADIO_PARAMS parameters{};
    parameters.dwSize = sizeof(parameters);
    HANDLE rawRadio = nullptr;
    HBLUETOOTH_RADIO_FIND find = BluetoothFindFirstRadio(&parameters, &rawRadio);
    if (find == nullptr) return;
    size_t radios = 0;
    size_t devices = 0;
    std::set<std::wstring> seenDeviceAddressDigests;
    do
    {
        UniqueHandle radio(rawRadio);
        BLUETOOTH_RADIO_INFO info{};
        info.dwSize = sizeof(info);
        if (BluetoothGetRadioInfo(radio.get(), &info) == ERROR_SUCCESS)
        {
            const std::wstring label = L"bluetooth" + std::to_wstring(radios++);
            collector.AddBinary(L"bluetooth", L"BluetoothGetRadioInfo", L"radio address",
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(info.address.rgBytes),
                    sizeof(info.address.rgBytes)), IdentityStrength::Medium, true,
                label + L"/address", false, true);
            collector.Add(L"bluetooth", L"BluetoothGetRadioInfo", L"radio name", info.szName,
                IdentityStrength::Weak, true, label + L"/name", false, true);
        }

        BLUETOOTH_DEVICE_SEARCH_PARAMS search{};
        search.dwSize = sizeof(search);
        search.fReturnAuthenticated = TRUE;
        search.fReturnRemembered = TRUE;
        search.fReturnConnected = TRUE;
        search.fReturnUnknown = FALSE;
        search.fIssueInquiry = FALSE;
        search.hRadio = radio.get();
        BLUETOOTH_DEVICE_INFO device{};
        device.dwSize = sizeof(device);
        HBLUETOOTH_DEVICE_FIND deviceFind = BluetoothFindFirstDevice(&search, &device);
        if (deviceFind != nullptr)
        {
            do
            {
                if (devices >= 256) break;
                ULONGLONG address = device.Address.ullLong;
                const std::wstring addressDigest = Sha256Hex(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte*>(&address), sizeof(address)));
                if (address != 0 && !addressDigest.empty() &&
                    seenDeviceAddressDigests.insert(addressDigest).second)
                {
                    const std::wstring deviceLabel =
                        L"bluetooth-device" + std::to_wstring(devices++);
                    collector.AddBinary(L"bluetooth", L"BluetoothFindFirstDevice",
                        L"remembered device address",
                        std::span<const std::byte>(
                            reinterpret_cast<const std::byte*>(&address), sizeof(address)),
                        IdentityStrength::Weak, true,
                        deviceLabel + L"/address", false, true);
                    collector.Add(L"bluetooth", L"BluetoothFindFirstDevice",
                        L"remembered device name", device.szName,
                        IdentityStrength::Context, false,
                        deviceLabel + L"/name", false, true);
                }
                SecureZeroMemory(&address, sizeof(address));
                SecureZeroMemory(&device, sizeof(device));
                device.dwSize = sizeof(device);
            } while (BluetoothFindNextDevice(deviceFind, &device));
            BluetoothFindDeviceClose(deviceFind);
        }
        SecureZeroMemory(&info, sizeof(info));
        rawRadio = nullptr;
    } while (BluetoothFindNextRadio(find, &rawRadio));
    BluetoothFindRadioClose(find);
    reporter.Add(FindingSeverity::Info, L"hwid/peripheral",
        L"Collected supported identity properties for " + std::to_wstring(radios) +
        L" Bluetooth radios and " + std::to_wstring(devices) +
        L" remembered devices as peripheral-only evidence");
}

#pragma pack(push, 1)
struct AcpiDescriptionHeader
{
    DWORD signature;
    DWORD length;
    BYTE revision;
    BYTE checksum;
    char oemId[6];
    char oemTableId[8];
    DWORD oemRevision;
    DWORD creatorId;
    DWORD creatorRevision;
};
#pragma pack(pop)

void CollectAcpiIdentity(IdentityCollector& collector, Reporter& reporter)
{
    const UINT required = EnumSystemFirmwareTables(kAcpiProvider, nullptr, 0);
    if (required == 0 || required > 1024 * 1024 || required % sizeof(DWORD) != 0) return;
    std::vector<DWORD> ids(required / sizeof(DWORD));
    const UINT returned = EnumSystemFirmwareTables(kAcpiProvider, ids.data(), required);
    if (returned == 0 || returned > required) return;
    const size_t count = std::min<size_t>(returned / sizeof(DWORD), 256);
    size_t parsed = 0;
    for (size_t index = 0; index < count; ++index)
    {
        const UINT tableSize = GetSystemFirmwareTable(kAcpiProvider, ids[index], nullptr, 0);
        if (tableSize < sizeof(AcpiDescriptionHeader) || tableSize > 4 * 1024 * 1024) continue;
        std::vector<std::byte> table(tableSize);
        const UINT written = GetSystemFirmwareTable(kAcpiProvider, ids[index], table.data(), tableSize);
        if (written < sizeof(AcpiDescriptionHeader) || written > table.size()) continue;
        const auto* header = reinterpret_cast<const AcpiDescriptionHeader*>(table.data());
        if (header->length < sizeof(AcpiDescriptionHeader) || header->length > written) continue;
        const std::wstring label = L"acpi" + std::to_wstring(index);
        collector.Add(L"firmware", L"ACPI", L"ACPI OEM identity " + std::to_wstring(index),
            FixedAnsi(reinterpret_cast<const UCHAR*>(header->oemId), sizeof(header->oemId)) + L"/" +
            FixedAnsi(reinterpret_cast<const UCHAR*>(header->oemTableId), sizeof(header->oemTableId)) +
            L"/" + std::to_wstring(header->oemRevision), IdentityStrength::Weak, true,
            label + L"/oem");
        collector.AddDigest(L"firmware", L"ACPI", L"ACPI table digest " + std::to_wstring(index),
            std::span<const std::byte>(table.data(), header->length), IdentityStrength::Weak, true,
            label + L"/digest");
        ++parsed;
        SecureZeroMemory(table.data(), table.size());
    }
    reporter.Add(FindingSeverity::Info, L"hwid/firmware",
        L"Parsed " + std::to_wstring(parsed) + L" bounded ACPI table identities");
}
} // namespace

void ScanHardwareIdentity(Reporter& reporter)
{
    IdentityCollector collector;
    CollectRegistryIdentity(collector);
    CollectSmbios(collector, reporter);
    CollectPhysicalStorage(collector, reporter);
    CollectVolumes(collector, reporter);
    CollectPnpIdentity(collector, reporter);
    CollectNetworkIdentity(collector, reporter);
    CollectMonitorEdid(collector, reporter);
    CollectBatteryIdentity(collector, reporter);
    CollectHidSerials(collector, reporter);
    CollectBluetoothRadios(collector, reporter);
    CollectAcpiIdentity(collector, reporter);
    collector.Report(reporter);
}
