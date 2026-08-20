#pragma once

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <string>
#include <string_view>

namespace oac
{
class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : value_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() noexcept
    {
        const HANDLE value = value_;
        value_ = nullptr;
        return value;
    }

    void reset(HANDLE value = nullptr) noexcept
    {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE)
            CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_;
};

class UniqueServiceHandle
{
public:
    explicit UniqueServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~UniqueServiceHandle() { reset(); }

    UniqueServiceHandle(const UniqueServiceHandle&) = delete;
    UniqueServiceHandle& operator=(const UniqueServiceHandle&) = delete;

    UniqueServiceHandle(UniqueServiceHandle&& other) noexcept : value_(other.release()) {}
    UniqueServiceHandle& operator=(UniqueServiceHandle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

    SC_HANDLE release() noexcept
    {
        const SC_HANDLE value = value_;
        value_ = nullptr;
        return value;
    }

    void reset(SC_HANDLE value = nullptr) noexcept
    {
        if (value_ != nullptr) CloseServiceHandle(value_);
        value_ = value;
    }

private:
    SC_HANDLE value_;
};

class RegistryKey
{
public:
    explicit RegistryKey(HKEY value = nullptr) noexcept : value_(value) {}
    ~RegistryKey() { reset(); }

    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;

    RegistryKey(RegistryKey&& other) noexcept : value_(other.release()) {}
    RegistryKey& operator=(RegistryKey&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] HKEY get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

    HKEY* put() noexcept
    {
        reset();
        return &value_;
    }

    HKEY release() noexcept
    {
        const HKEY value = value_;
        value_ = nullptr;
        return value;
    }

    void reset(HKEY value = nullptr) noexcept
    {
        if (value_ != nullptr) RegCloseKey(value_);
        value_ = value;
    }

private:
    HKEY value_;
};

template<typename Function>
Function ResolveFunction(HMODULE module, const char* name) noexcept
{
    const FARPROC raw = module != nullptr ? GetProcAddress(module, name) : nullptr;
    static_assert(sizeof(Function) == sizeof(raw));
    return reinterpret_cast<Function>(raw);
}

inline std::wstring Lowercase(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t character)
        {
            return static_cast<wchar_t>(std::towlower(character));
        });
    return value;
}

inline std::string Utf8(std::wstring_view value)
{
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) return {};

    std::string result(static_cast<size_t>(required), '\0');
    const int converted = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr);
    return converted == required ? result : std::string{};
}

inline bool EnablePrivilege(const wchar_t* name)
{
    HANDLE rawToken = nullptr;
    if (name == nullptr || !OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &rawToken))
        return false;

    UniqueHandle token(rawToken);
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(
            nullptr, name, &privileges.Privileges[0].Luid))
        return false;

    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    return AdjustTokenPrivileges(
               token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr) &&
        GetLastError() == ERROR_SUCCESS;
}
}
