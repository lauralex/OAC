#include "service.hpp"

#include <Windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <userenv.h>

#include <array>
#include <cstddef>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include "..\shared\oac_ipc.h"
#include "..\shared\protocol\oac_v5.h"
#include "..\shared\protocol\oac_validate.h"

namespace
{
constexpr wchar_t kDevicePath[] = L"\\\\.\\OAC";
constexpr DWORD kPipeIoTimeoutMs = 5000;
constexpr ULONG kLaunchTimeToLiveMs = 10000;
constexpr wchar_t kPipeSddl[] =
    L"O:SYG:SYD:P"
    L"(D;;GA;;;NU)"
    L"(A;;GA;;;SY)"
    L"(A;;GA;;;" OAC_SERVICE_SID L")"
    L"(A;;0x0012019B;;;IU)";

class UniqueHandle
{
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() noexcept
    {
        const HANDLE result = handle_;
        handle_ = nullptr;
        return result;
    }

    void reset(HANDLE handle = nullptr) noexcept
    {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
        handle_ = handle;
    }

private:
    HANDLE handle_;
};

class LocalBuffer
{
public:
    ~LocalBuffer()
    {
        if (value_ != nullptr) LocalFree(value_);
    }
    LocalBuffer(const LocalBuffer&) = delete;
    LocalBuffer& operator=(const LocalBuffer&) = delete;
    LocalBuffer() = default;

    void** put() noexcept { return &value_; }
    [[nodiscard]] void* get() const noexcept { return value_; }

private:
    void* value_ = nullptr;
};

class EnvironmentBlock
{
public:
    ~EnvironmentBlock()
    {
        if (value_ != nullptr) DestroyEnvironmentBlock(value_);
    }
    EnvironmentBlock(const EnvironmentBlock&) = delete;
    EnvironmentBlock& operator=(const EnvironmentBlock&) = delete;
    EnvironmentBlock() = default;

    void** put() noexcept { return &value_; }
    [[nodiscard]] void* get() const noexcept { return value_; }

private:
    void* value_ = nullptr;
};

bool QueryToken(
    HANDLE token,
    TOKEN_INFORMATION_CLASS informationClass,
    std::vector<std::byte>& buffer,
    DWORD& error)
{
    DWORD needed = 0;
    if (GetTokenInformation(token, informationClass, nullptr, 0, &needed) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 ||
        needed > 1024u * 1024u)
    {
        error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
        return false;
    }

    buffer.resize(needed);
    if (!GetTokenInformation(
            token,
            informationClass,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &needed))
    {
        error = GetLastError();
        return false;
    }
    return true;
}

template<typename Value>
bool QueryTokenValue(
    HANDLE token,
    TOKEN_INFORMATION_CLASS informationClass,
    Value& value,
    DWORD& error)
{
    DWORD returned = 0;
    if (!GetTokenInformation(
            token,
            informationClass,
            &value,
            static_cast<DWORD>(sizeof(value)),
            &returned) || returned != sizeof(value))
    {
        error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_INVALID_DATA;
        return false;
    }
    return true;
}

bool GroupsContain(
    const TOKEN_GROUPS* groups,
    PSID sid,
    DWORD requiredAttributes,
    DWORD rejectedAttributes)
{
    if (groups == nullptr || !IsValidSid(sid)) return false;
    for (DWORD index = 0; index < groups->GroupCount; ++index)
    {
        const SID_AND_ATTRIBUTES& group = groups->Groups[index];
        if (IsValidSid(group.Sid) && EqualSid(group.Sid, sid) &&
            (group.Attributes & requiredAttributes) == requiredAttributes &&
            (group.Attributes & rejectedAttributes) == 0)
            return true;
    }
    return false;
}

bool GroupsContainWellKnown(
    const TOKEN_GROUPS* groups,
    WELL_KNOWN_SID_TYPE type,
    DWORD requiredAttributes = 0)
{
    if (groups == nullptr) return false;
    for (DWORD index = 0; index < groups->GroupCount; ++index)
    {
        const SID_AND_ATTRIBUTES& group = groups->Groups[index];
        if (IsValidSid(group.Sid) && IsWellKnownSid(group.Sid, type) &&
            (group.Attributes & requiredAttributes) == requiredAttributes)
            return true;
    }
    return false;
}

bool PrivilegesContain(
    const TOKEN_PRIVILEGES* privileges,
    const wchar_t* name)
{
    if (privileges == nullptr || name == nullptr) return false;
    LUID required{};
    if (!LookupPrivilegeValueW(nullptr, name, &required)) return false;
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
    {
        if (privileges->Privileges[index].Luid.LowPart == required.LowPart &&
            privileges->Privileges[index].Luid.HighPart == required.HighPart)
            return true;
    }
    return false;
}

DWORD VerifyServiceIdentity()
{
    UniqueHandle token;
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
        return GetLastError();
    token.reset(rawToken);

    DWORD error = ERROR_SUCCESS;
    TOKEN_TYPE tokenType{};
    DWORD sessionId = MAXDWORD;
    if (!QueryTokenValue(token.get(), TokenType, tokenType, error) ||
        tokenType != TokenPrimary ||
        !QueryTokenValue(token.get(), TokenSessionId, sessionId, error) ||
        sessionId != 0 || !IsTokenRestricted(token.get()))
        return error == ERROR_SUCCESS ? ERROR_SERVICE_LOGON_FAILED : error;

    std::vector<std::byte> userBuffer;
    std::vector<std::byte> groupBuffer;
    std::vector<std::byte> restrictedBuffer;
    std::vector<std::byte> privilegeBuffer;
    if (!QueryToken(token.get(), TokenUser, userBuffer, error) ||
        !QueryToken(token.get(), TokenGroups, groupBuffer, error) ||
        !QueryToken(token.get(), TokenRestrictedSids, restrictedBuffer, error) ||
        !QueryToken(token.get(), TokenPrivileges, privilegeBuffer, error))
        return error;

    const auto* user = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    if (!IsValidSid(user->User.Sid) ||
        !IsWellKnownSid(user->User.Sid, WinLocalSystemSid))
        return ERROR_SERVICE_LOGON_FAILED;

    LocalBuffer serviceSid;
    if (!ConvertStringSidToSidW(
            OAC_SERVICE_SID,
            reinterpret_cast<PSID*>(serviceSid.put())) ||
        !IsValidSid(serviceSid.get()))
        return GetLastError();

    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(groupBuffer.data());
    const auto* restricted = reinterpret_cast<const TOKEN_GROUPS*>(
        restrictedBuffer.data());
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(
        privilegeBuffer.data());
    if (!GroupsContain(
            groups,
            serviceSid.get(),
            SE_GROUP_ENABLED,
            SE_GROUP_USE_FOR_DENY_ONLY) ||
        !GroupsContain(restricted, serviceSid.get(), 0, 0) ||
        !PrivilegesContain(privileges, SE_ASSIGNPRIMARYTOKEN_NAME) ||
        !PrivilegesContain(privileges, SE_CHANGE_NOTIFY_NAME) ||
        !PrivilegesContain(privileges, SE_IMPERSONATE_NAME) ||
        !PrivilegesContain(privileges, SE_INCREASE_QUOTA_NAME))
        return ERROR_SERVICE_LOGON_FAILED;

    DWORD accountSidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE use{};
    (void)LookupAccountNameW(
        nullptr,
        OAC_SERVICE_ACCOUNT,
        nullptr,
        &accountSidSize,
        nullptr,
        &domainSize,
        &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || accountSidSize == 0 ||
        accountSidSize > SECURITY_MAX_SID_SIZE || domainSize > 256)
        return ERROR_SERVICE_LOGON_FAILED;

    std::vector<std::byte> accountSid(accountSidSize);
    std::vector<wchar_t> domain(domainSize);
    if (!LookupAccountNameW(
            nullptr,
            OAC_SERVICE_ACCOUNT,
            accountSid.data(),
            &accountSidSize,
            domain.empty() ? nullptr : domain.data(),
            &domainSize,
            &use) ||
        !IsValidSid(accountSid.data()) ||
        !EqualSid(accountSid.data(), serviceSid.get()))
        return ERROR_SERVICE_LOGON_FAILED;

    return ERROR_SUCCESS;
}

bool MakeRequestId(ULONGLONG& requestId)
{
    requestId = 0;
    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(&requestId),
        static_cast<ULONG>(sizeof(requestId)),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) && requestId != 0;
}

bool SameLuid(const LUID& left, const LUID& right) noexcept
{
    return left.LowPart == right.LowPart && left.HighPart == right.HighPart;
}

struct ClientIdentity
{
    UniqueHandle process;
    UniqueHandle primaryToken;
    DWORD processId = 0;
    DWORD sessionId = 0;
    bool revertFailed = false;
};

DWORD AuthorizeClient(HANDLE pipe, ClientIdentity& identity)
{
    ULONG clientPid = 0;
    ULONG pipeSessionId = 0;
    if (!GetNamedPipeClientProcessId(pipe, &clientPid) || clientPid == 0 ||
        clientPid == GetCurrentProcessId() ||
        !GetNamedPipeClientSessionId(pipe, &pipeSessionId) || pipeSessionId == 0)
        return ERROR_ACCESS_DENIED;

    if (!ImpersonateNamedPipeClient(pipe)) return GetLastError();

    DWORD result = ERROR_SUCCESS;
    UniqueHandle threadToken;
    UniqueHandle primaryToken;
    std::vector<std::byte> threadUserBuffer;
    std::vector<std::byte> groupBuffer;
    std::vector<std::byte> integrityBuffer;
    TOKEN_STATISTICS threadStatistics{};
    DWORD threadSessionId = MAXDWORD;
    try
    {
        HANDLE rawToken = nullptr;
        if (!OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                TRUE,
                &rawToken))
        {
            result = GetLastError();
        }
        else
        {
            threadToken.reset(rawToken);
        }

        DWORD error = ERROR_SUCCESS;
        TOKEN_TYPE threadType{};
        SECURITY_IMPERSONATION_LEVEL level{};
        DWORD appContainer = 0;
        if (result == ERROR_SUCCESS &&
            (!QueryTokenValue(
                 threadToken.get(), TokenType, threadType, error) ||
             threadType != TokenImpersonation ||
             !QueryTokenValue(
                 threadToken.get(), TokenImpersonationLevel, level, error) ||
             level != SecurityImpersonation ||
             !QueryTokenValue(
                 threadToken.get(), TokenSessionId, threadSessionId, error) ||
             !QueryTokenValue(
                 threadToken.get(), TokenIsAppContainer, appContainer, error)))
        {
            result = error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error;
        }

        if (result == ERROR_SUCCESS &&
            (!QueryToken(
                 threadToken.get(), TokenUser, threadUserBuffer, error) ||
             !QueryToken(
                 threadToken.get(), TokenGroups, groupBuffer, error) ||
             !QueryToken(
                 threadToken.get(),
                 TokenIntegrityLevel,
                 integrityBuffer,
                 error) ||
             !QueryTokenValue(
                 threadToken.get(), TokenStatistics, threadStatistics, error)))
            result = error;

        if (result == ERROR_SUCCESS)
        {
            const auto* threadUser = reinterpret_cast<const TOKEN_USER*>(
                threadUserBuffer.data());
            const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(
                groupBuffer.data());
            const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(
                integrityBuffer.data());
            const UCHAR subAuthorityCount = IsValidSid(label->Label.Sid)
                ? *GetSidSubAuthorityCount(label->Label.Sid)
                : 0;
            const DWORD integrity = subAuthorityCount != 0
                ? *GetSidSubAuthority(label->Label.Sid, subAuthorityCount - 1)
                : 0;
            if (threadSessionId != pipeSessionId ||
                appContainer != 0 ||
                !IsValidSid(threadUser->User.Sid) ||
                IsWellKnownSid(threadUser->User.Sid, WinLocalSystemSid) ||
                IsWellKnownSid(threadUser->User.Sid, WinLocalServiceSid) ||
                IsWellKnownSid(threadUser->User.Sid, WinNetworkServiceSid) ||
                IsWellKnownSid(threadUser->User.Sid, WinAnonymousSid) ||
                !GroupsContainWellKnown(
                    groups, WinInteractiveSid, SE_GROUP_ENABLED) ||
                GroupsContainWellKnown(
                    groups, WinNetworkSid, SE_GROUP_ENABLED) ||
                integrity < SECURITY_MANDATORY_MEDIUM_RID)
                result = ERROR_ACCESS_DENIED;
        }

        if (result == ERROR_SUCCESS)
        {
            HANDLE rawPrimaryToken = nullptr;
            if (!DuplicateTokenEx(
                    threadToken.get(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                    nullptr,
                    SecurityImpersonation,
                    TokenPrimary,
                    &rawPrimaryToken))
            {
                result = GetLastError();
            }
            else
            {
                primaryToken.reset(rawPrimaryToken);
                TOKEN_TYPE primaryType{};
                TOKEN_STATISTICS primaryStatistics{};
                DWORD primarySessionId = MAXDWORD;
                if (!QueryTokenValue(
                        primaryToken.get(),
                        TokenType,
                        primaryType,
                        error) ||
                    primaryType != TokenPrimary ||
                    !QueryTokenValue(
                        primaryToken.get(),
                        TokenSessionId,
                        primarySessionId,
                        error) ||
                    !QueryTokenValue(
                        primaryToken.get(),
                        TokenStatistics,
                        primaryStatistics,
                        error) ||
                    primarySessionId != pipeSessionId ||
                    !SameLuid(
                        primaryStatistics.AuthenticationId,
                        threadStatistics.AuthenticationId))
                {
                    result = error == ERROR_SUCCESS
                        ? ERROR_ACCESS_DENIED
                        : error;
                }
            }
        }
    }
    catch (const std::bad_alloc&)
    {
        result = ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        result = ERROR_UNHANDLED_EXCEPTION;
    }

    if (!RevertToSelf())
    {
        identity.revertFailed = true;
        result = GetLastError();
        if (result == ERROR_SUCCESS) result = ERROR_CANNOT_IMPERSONATE;
    }
    if (identity.revertFailed || result != ERROR_SUCCESS) return result;

    UniqueHandle process(OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE,
        clientPid));
    if (!process) return GetLastError();

    UniqueHandle processToken;
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(process.get(), TOKEN_QUERY, &rawToken))
        return GetLastError();
    processToken.reset(rawToken);

    try
    {
        DWORD error = ERROR_SUCCESS;
        DWORD processSessionId = MAXDWORD;
        TOKEN_STATISTICS processStatistics{};
        std::vector<std::byte> processUserBuffer;
        if (!QueryTokenValue(
                processToken.get(), TokenSessionId, processSessionId, error) ||
            !QueryTokenValue(
                processToken.get(),
                TokenStatistics,
                processStatistics,
                error) ||
            !QueryToken(
                processToken.get(), TokenUser, processUserBuffer, error))
            return error;

        const auto* threadUser = reinterpret_cast<const TOKEN_USER*>(
            threadUserBuffer.data());
        const auto* processUser = reinterpret_cast<const TOKEN_USER*>(
            processUserBuffer.data());
        DWORD observedSessionId = MAXDWORD;
        if (processSessionId != pipeSessionId ||
            GetProcessId(process.get()) != clientPid ||
            WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT ||
            !ProcessIdToSessionId(clientPid, &observedSessionId) ||
            observedSessionId != pipeSessionId ||
            !IsValidSid(processUser->User.Sid) ||
            !EqualSid(threadUser->User.Sid, processUser->User.Sid) ||
            !SameLuid(
                threadStatistics.AuthenticationId,
                processStatistics.AuthenticationId))
            return ERROR_ACCESS_DENIED;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        return ERROR_UNHANDLED_EXCEPTION;
    }

    identity.process = std::move(process);
    identity.primaryToken = std::move(primaryToken);
    identity.processId = clientPid;
    identity.sessionId = pipeSessionId;
    return ERROR_SUCCESS;
}

HANDLE CreateControlPipe(bool firstInstance, DWORD& error)
{
    LocalBuffer descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kPipeSddl,
            SDDL_REVISION_1,
            reinterpret_cast<PSECURITY_DESCRIPTOR*>(descriptor.put()),
            nullptr))
    {
        error = GetLastError();
        return INVALID_HANDLE_VALUE;
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor.get();
    attributes.bInheritHandle = FALSE;
    const DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
        (firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
    HANDLE pipe = CreateNamedPipeW(
        OAC_PIPE_NAME,
        openMode,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS,
        2,
        OAC_IPC_MAX_MESSAGE_SIZE,
        OAC_IPC_MAX_MESSAGE_SIZE,
        0,
        &attributes);
    if (pipe == INVALID_HANDLE_VALUE) error = GetLastError();
    return pipe;
}

DWORD WaitForPipeIo(
    HANDLE pipe,
    HANDLE stopEvent,
    OVERLAPPED& overlapped,
    DWORD& transferred,
    DWORD timeout)
{
    HANDLE waits[] = {stopEvent, overlapped.hEvent};
    const DWORD wait = WaitForMultipleObjects(2, waits, FALSE, timeout);
    if (wait != WAIT_OBJECT_0 + 1)
    {
        const DWORD error = wait == WAIT_OBJECT_0
            ? ERROR_OPERATION_ABORTED
            : wait == WAIT_TIMEOUT
                ? ERROR_TIMEOUT
                : GetLastError();
        (void)CancelIoEx(pipe, &overlapped);
        (void)GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
    }
    if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE))
        return GetLastError();
    return ERROR_SUCCESS;
}

DWORD ConnectClient(HANDLE pipe, HANDLE stopEvent)
{
    UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return GetLastError();
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    if (ConnectNamedPipe(pipe, &overlapped)) return ERROR_SUCCESS;

    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) return ERROR_SUCCESS;
    if (error != ERROR_IO_PENDING) return error;
    DWORD transferred = 0;
    return WaitForPipeIo(
        pipe, stopEvent, overlapped, transferred, INFINITE);
}

DWORD ReadMessage(
    HANDLE pipe,
    HANDLE stopEvent,
    void* buffer,
    DWORD capacity,
    DWORD& bytesRead)
{
    UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return GetLastError();
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    if (ReadFile(pipe, buffer, capacity, &bytesRead, &overlapped))
        return ERROR_SUCCESS;

    const DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) return error;
    return WaitForPipeIo(
        pipe, stopEvent, overlapped, bytesRead, kPipeIoTimeoutMs);
}

DWORD WriteMessage(
    HANDLE pipe,
    HANDLE stopEvent,
    const void* buffer,
    DWORD size)
{
    UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return GetLastError();
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD bytesWritten = 0;
    if (!WriteFile(pipe, buffer, size, &bytesWritten, &overlapped))
    {
        const DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) return error;
        const DWORD waitError = WaitForPipeIo(
            pipe,
            stopEvent,
            overlapped,
            bytesWritten,
            kPipeIoTimeoutMs);
        if (waitError != ERROR_SUCCESS) return waitError;
    }
    return bytesWritten == size ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}

bool ValidRequest(const OAC_IPC_REQUEST& request, DWORD bytesRead)
{
    constexpr DWORD requestSize = static_cast<DWORD>(sizeof(request));
    return OacIpcHeaderMatches(
            &request.Header,
            bytesRead,
            requestSize,
            request.Header.Type) &&
        request.Reserved == 0 &&
        (request.Header.Type == OAC_IPC_TYPE_HELLO_REQUEST ||
         request.Header.Type == OAC_IPC_TYPE_STATUS_REQUEST);
}

DWORD ReadFinalPath(
    HANDLE file,
    DWORD flags,
    std::wstring& path)
{
    const DWORD required = GetFinalPathNameByHandleW(
        file, nullptr, 0, flags);
    if (required == 0) return GetLastError();
    if (required > 32768) return ERROR_FILENAME_EXCED_RANGE;

    std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1u);
    const DWORD written = GetFinalPathNameByHandleW(
        file,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        flags);
    if (written == 0) return GetLastError();
    if (written >= buffer.size()) return ERROR_INSUFFICIENT_BUFFER;
    path.assign(buffer.data(), written);
    return ERROR_SUCCESS;
}

DWORD OpenClientExecutable(
    HANDLE pipe,
    const OAC_IPC_LAUNCH_REQUEST& request,
    UniqueHandle& executable,
    std::wstring& finalDosPath,
    std::array<WCHAR, OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS>& finalNtPath,
    ULONG& finalNtPathLength,
    std::array<WCHAR, OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS>&
        canonicalDosDevicePath,
    ULONG& canonicalDosDevicePathLength,
    bool& revertFailed)
{
    static_assert(sizeof(wchar_t) == sizeof(uint16_t));
    std::wstring requestedPath;
    requestedPath.reserve(request.ExecutablePathLength);
    for (ULONG index = 0; index < request.ExecutablePathLength; ++index)
        requestedPath.push_back(static_cast<wchar_t>(request.ExecutablePath[index]));

    if (!ImpersonateNamedPipeClient(pipe)) return GetLastError();
    const HANDLE rawExecutable = CreateFileW(
        requestedPath.c_str(),
        GENERIC_READ | FILE_EXECUTE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    DWORD error = rawExecutable == INVALID_HANDLE_VALUE
        ? GetLastError()
        : ERROR_SUCCESS;
    if (!RevertToSelf())
    {
        revertFailed = true;
        const DWORD revertError = GetLastError();
        if (rawExecutable != INVALID_HANDLE_VALUE) CloseHandle(rawExecutable);
        return revertError == ERROR_SUCCESS
            ? ERROR_CANNOT_IMPERSONATE
            : revertError;
    }
    if (error != ERROR_SUCCESS) return error;
    executable.reset(rawExecutable);

    if (GetFileType(executable.get()) != FILE_TYPE_DISK)
        return ERROR_FILE_INVALID;
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(executable.get(), &information))
        return GetLastError();
    if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return ERROR_DIRECTORY;

    error = ReadFinalPath(
        executable.get(),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        finalDosPath);
    if (error != ERROR_SUCCESS) return error;
    if (finalDosPath.size() < 7 || finalDosPath.rfind(L"\\\\?\\", 0) != 0 ||
        finalDosPath.size() >= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS ||
        !((finalDosPath[4] >= L'A' && finalDosPath[4] <= L'Z') ||
          (finalDosPath[4] >= L'a' && finalDosPath[4] <= L'z')) ||
        finalDosPath[5] != L':' || finalDosPath[6] != L'\\')
    {
        return ERROR_BAD_PATHNAME;
    }
    const wchar_t driveRoot[] =
    {
        finalDosPath[4], L':', L'\\', L'\0'
    };
    if (GetDriveTypeW(driveRoot) != DRIVE_FIXED)
        return ERROR_NOT_SUPPORTED;

    canonicalDosDevicePath.fill(L'\0');
    canonicalDosDevicePath[0] = L'\\';
    canonicalDosDevicePath[1] = L'?';
    canonicalDosDevicePath[2] = L'?';
    canonicalDosDevicePath[3] = L'\\';
    for (size_t index = 4; index < finalDosPath.size(); ++index)
        canonicalDosDevicePath[index] = finalDosPath[index];
    canonicalDosDevicePathLength = static_cast<ULONG>(finalDosPath.size());
    if (OacValidateCanonicalDosDevicePath(
            canonicalDosDevicePath.data(),
            canonicalDosDevicePathLength) != OAC_V5_VALID)
    {
        return ERROR_BAD_PATHNAME;
    }

    std::wstring ntPath;
    error = ReadFinalPath(
        executable.get(),
        FILE_NAME_NORMALIZED | VOLUME_NAME_NT,
        ntPath);
    if (error != ERROR_SUCCESS) return error;
    if (ntPath.empty() ||
        ntPath.size() >= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS)
    {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    finalNtPath.fill(L'\0');
    for (size_t index = 0; index < ntPath.size(); ++index)
        finalNtPath[index] = ntPath[index];
    finalNtPathLength = static_cast<ULONG>(ntPath.size());
    if (OacValidateCanonicalNtPath(
            finalNtPath.data(),
            finalNtPathLength) != OAC_V5_VALID)
    {
        return ERROR_BAD_PATHNAME;
    }
    return ERROR_SUCCESS;
}

bool InitializeDriverRequest(
    OAC_V5_REQUEST_HEADER& header,
    ULONG size,
    OAC_V5_MESSAGE_TYPE messageType,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation)
{
    header.Version = OAC_V5_VERSION;
    header.Size = size;
    header.SessionId = sessionId;
    header.Generation = generation;
    header.MessageType = messageType;
    return MakeRequestId(header.RequestId);
}

DWORD ArmLaunch(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    const std::array<WCHAR, OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS>& ntPath,
    ULONG ntPathLength,
    const std::array<WCHAR, OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS>&
        dosDevicePath,
    ULONG dosDevicePathLength,
    OAC_ARM_LAUNCH_RESPONSE& response)
{
    OAC_ARM_LAUNCH_REQUEST request{};
    if (!InitializeDriverRequest(
            request.Header,
            static_cast<ULONG>(sizeof(request)),
            OAC_MESSAGE_ARM_LAUNCH,
            sessionId,
            generation))
    {
        return ERROR_GEN_FAILURE;
    }
    request.TimeToLiveMilliseconds = kLaunchTimeToLiveMs;
    request.CanonicalNtPathLength = ntPathLength;
    request.CanonicalDosDevicePathLength = dosDevicePathLength;
    CopyMemory(
        request.CanonicalNtPath,
        ntPath.data(),
        static_cast<SIZE_T>(ntPathLength) * sizeof(WCHAR));
    CopyMemory(
        request.CanonicalDosDevicePath,
        dosDevicePath.data(),
        static_cast<SIZE_T>(dosDevicePathLength) * sizeof(WCHAR));

    DWORD returned = 0;
    if (!DeviceIoControl(
            driver,
            IOCTL_OAC_ARM_LAUNCH,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    if (OacValidateArmLaunchResponse(&response, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &request.Header,
            &response.Header) != OAC_V5_VALID ||
        response.Header.Status != 0 ||
        response.Header.Reason != OAC_V5_REASON_NONE ||
        response.Header.Flags != 0)
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

DWORD CancelLaunch(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    const OAC_LAUNCH_ID& launchId)
{
    OAC_CANCEL_LAUNCH_REQUEST request{};
    if (!InitializeDriverRequest(
            request.Header,
            static_cast<ULONG>(sizeof(request)),
            OAC_MESSAGE_CANCEL_LAUNCH,
            sessionId,
            generation))
    {
        return ERROR_GEN_FAILURE;
    }
    request.LaunchId = launchId;
    OAC_CANCEL_LAUNCH_RESPONSE response{};
    DWORD returned = 0;
    if (!DeviceIoControl(
            driver,
            IOCTL_OAC_CANCEL_LAUNCH,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    if (OacValidateCancelLaunchResponse(&response, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &request.Header,
            &response.Header) != OAC_V5_VALID ||
        response.Header.Status != 0 ||
        response.Header.Reason != OAC_V5_REASON_NONE)
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

DWORD ConfirmTarget(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    const OAC_LAUNCH_ID& launchId,
    HANDLE process,
    OAC_CONFIRM_TARGET_RESPONSE& response)
{
    OAC_CONFIRM_TARGET_REQUEST request{};
    if (!InitializeDriverRequest(
            request.Header,
            static_cast<ULONG>(sizeof(request)),
            OAC_MESSAGE_CONFIRM_TARGET,
            sessionId,
            generation))
    {
        return ERROR_GEN_FAILURE;
    }
    request.LaunchId = launchId;
    request.TargetProcessHandle = static_cast<ULONGLONG>(
        reinterpret_cast<ULONG_PTR>(process));

    DWORD returned = 0;
    if (!DeviceIoControl(
            driver,
            IOCTL_OAC_CONFIRM_TARGET,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    if (OacValidateConfirmTargetResponse(&response, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &request.Header,
            &response.Header) != OAC_V5_VALID ||
        response.Header.Status != 0 ||
        response.Header.Reason != OAC_V5_REASON_NONE ||
        response.Header.Flags != 0 ||
        response.TargetProcessId != GetProcessId(process))
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

DWORD ReadDriverStatus(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    OAC_V5_STATUS_RESPONSE& response)
{
    OAC_V5_STATUS_REQUEST request{};
    if (!InitializeDriverRequest(
            request.Header,
            static_cast<ULONG>(sizeof(request)),
            OAC_V5_MESSAGE_GET_STATUS,
            sessionId,
            generation))
    {
        return ERROR_GEN_FAILURE;
    }
    DWORD returned = 0;
    if (!DeviceIoControl(
            driver,
            IOCTL_OAC_V5_GET_STATUS,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    if (OacV5ValidateStatusResponse(&response, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &request.Header,
            &response.Header) != OAC_V5_VALID ||
        response.Header.Status != 0 ||
        response.Header.Reason != OAC_V5_REASON_NONE)
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

uint32_t LaunchFailureDetailFromStatus(
    OAC_V5_REVOKE_REASON revokeReason) noexcept
{
    switch (revokeReason)
    {
    case OAC_V5_REVOKE_NONE:
        return OAC_IPC_LAUNCH_DETAIL_NONE;
    case OAC_REVOKE_LAUNCH_CANCELLED:
        return OAC_IPC_LAUNCH_DETAIL_CANCELLED;
    case OAC_REVOKE_LAUNCH_EXPIRED:
        return OAC_IPC_LAUNCH_DETAIL_EXPIRED;
    case OAC_REVOKE_LAUNCH_MISMATCH:
        return OAC_IPC_LAUNCH_DETAIL_PATH_MISMATCH;
    case OAC_REVOKE_TARGET_CONFIRMATION_FAILED:
        return OAC_IPC_LAUNCH_DETAIL_CONFIRMATION_FAILED;
    default:
        return OAC_IPC_LAUNCH_DETAIL_OTHER_REVOCATION;
    }
}

void CaptureLaunchFailureDetail(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    uint32_t& failureDetail) noexcept
{
    OAC_V5_STATUS_RESPONSE status{};
    if (ReadDriverStatus(driver, sessionId, generation, status) != ERROR_SUCCESS)
    {
        failureDetail = OAC_IPC_LAUNCH_DETAIL_STATUS_UNAVAILABLE;
        return;
    }
    failureDetail = LaunchFailureDetailFromStatus(status.RevokeReason);
}

bool SessionHasControl(ULONG state) noexcept
{
    return state == OAC_V5_SESSION_CLAIMED ||
        state == OAC_V5_SESSION_LAUNCH_PENDING ||
        state == OAC_V5_SESSION_TARGET_BOUND ||
        state == OAC_V5_SESSION_MONITORING;
}

void TerminateSuspendedProcess(HANDLE process) noexcept
{
    if (process == nullptr || process == INVALID_HANDLE_VALUE) return;
    (void)TerminateProcess(process, ERROR_PROCESS_ABORTED);
    (void)WaitForSingleObject(process, 5000);
}

DWORD LaunchTarget(
    HANDLE pipe,
    HANDLE stopEvent,
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    const OAC_IPC_LAUNCH_REQUEST& request,
    ClientIdentity& client,
    DWORD& targetProcessId,
    bool& driverSessionChanged,
    uint32_t& failureStage,
    uint32_t& failureDetail)
{
    targetProcessId = 0;
    driverSessionChanged = false;
    failureStage = OAC_IPC_LAUNCH_STAGE_AUTHORIZE_CLIENT;
    failureDetail = OAC_IPC_LAUNCH_DETAIL_NONE;
    if (!client.primaryToken || WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
        return ERROR_OPERATION_ABORTED;

    failureStage = OAC_IPC_LAUNCH_STAGE_OPEN_EXECUTABLE;
    UniqueHandle executable;
    std::wstring finalDosPath;
    std::array<WCHAR, OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS> finalNtPath{};
    ULONG finalNtPathLength = 0;
    std::array<WCHAR, OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS>
        canonicalDosDevicePath{};
    ULONG canonicalDosDevicePathLength = 0;
    DWORD error = OpenClientExecutable(
        pipe,
        request,
        executable,
        finalDosPath,
        finalNtPath,
        finalNtPathLength,
        canonicalDosDevicePath,
        canonicalDosDevicePathLength,
        client.revertFailed);
    if (error != ERROR_SUCCESS) return error;

    failureStage = OAC_IPC_LAUNCH_STAGE_CREATE_ENVIRONMENT;
    EnvironmentBlock environment;
    if (!CreateEnvironmentBlock(environment.put(), client.primaryToken.get(), FALSE))
        return GetLastError();

    failureStage = OAC_IPC_LAUNCH_STAGE_ARM_TICKET;
    OAC_ARM_LAUNCH_RESPONSE armed{};
    error = ArmLaunch(
        driver,
        sessionId,
        generation,
        finalNtPath,
        finalNtPathLength,
        canonicalDosDevicePath,
        canonicalDosDevicePathLength,
        armed);
    if (error != ERROR_SUCCESS) return error;
    driverSessionChanged = true;

    failureStage = OAC_IPC_LAUNCH_STAGE_CREATE_PROCESS;
    if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
    {
        (void)CancelLaunch(driver, sessionId, generation, armed.LaunchId);
        CaptureLaunchFailureDetail(
            driver,
            sessionId,
            generation,
            failureDetail);
        return ERROR_OPERATION_ABORTED;
    }

    std::wstring commandLine = L"\"" + finalDosPath + L"\"";
    std::vector<wchar_t> mutableCommandLine(
        commandLine.begin(),
        commandLine.end());
    mutableCommandLine.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    PROCESS_INFORMATION processInformation{};
    if (!CreateProcessAsUserW(
            client.primaryToken.get(),
            finalDosPath.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment.get(),
            nullptr,
            &startup,
            &processInformation))
    {
        error = GetLastError();
        (void)CancelLaunch(driver, sessionId, generation, armed.LaunchId);
        CaptureLaunchFailureDetail(
            driver,
            sessionId,
            generation,
            failureDetail);
        return error;
    }

    UniqueHandle process(processInformation.hProcess);
    UniqueHandle thread(processInformation.hThread);
    failureStage = OAC_IPC_LAUNCH_STAGE_CONFIRM_TARGET;
    OAC_CONFIRM_TARGET_RESPONSE confirmed{};
    error = ConfirmTarget(
        driver,
        sessionId,
        generation,
        armed.LaunchId,
        process.get(),
        confirmed);
    if (error != ERROR_SUCCESS)
    {
        CaptureLaunchFailureDetail(
            driver,
            sessionId,
            generation,
            failureDetail);
        TerminateSuspendedProcess(process.get());
        return error;
    }

    failureStage = OAC_IPC_LAUNCH_STAGE_VALIDATE_STATUS;
    OAC_V5_STATUS_RESPONSE status{};
    error = ReadDriverStatus(driver, sessionId, generation, status);
    if (error != ERROR_SUCCESS ||
        status.State != OAC_V5_SESSION_MONITORING ||
        status.TargetProcessId != confirmed.TargetProcessId ||
        status.TargetProcessId != processInformation.dwProcessId)
    {
        CaptureLaunchFailureDetail(
            driver,
            sessionId,
            generation,
            failureDetail);
        TerminateSuspendedProcess(process.get());
        return error == ERROR_SUCCESS ? ERROR_INVALID_STATE : error;
    }
    failureStage = OAC_IPC_LAUNCH_STAGE_RESUME_THREAD;
    if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
    {
        TerminateSuspendedProcess(process.get());
        return ERROR_OPERATION_ABORTED;
    }
    const DWORD previousSuspendCount = ResumeThread(thread.get());
    if (previousSuspendCount == static_cast<DWORD>(-1))
    {
        error = GetLastError();
        TerminateSuspendedProcess(process.get());
        return error;
    }
    if (previousSuspendCount != 1)
    {
        TerminateSuspendedProcess(process.get());
        return ERROR_INVALID_STATE;
    }

    targetProcessId = processInformation.dwProcessId;
    failureStage = OAC_IPC_LAUNCH_STAGE_NONE;
    failureDetail = OAC_IPC_LAUNCH_DETAIL_NONE;
    return ERROR_SUCCESS;
}

/* Driver negotiation is kept isolated so every startup path fails closed. */
DWORD OpenAndClaimDriver(
    HANDLE& driver,
    ULONG& version,
    ULONGLONG& capabilities,
    OAC_V5_SESSION_ID& sessionId,
    ULONGLONG& generation,
    OAC_SERVICE_FAILURE_STAGE& failureStage)
{
    failureStage = OAC_SERVICE_STAGE_DRIVER_OPEN;
    UniqueHandle candidate(CreateFileW(
        kDevicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!candidate) return GetLastError();

    failureStage = OAC_SERVICE_STAGE_DRIVER_NEGOTIATE;
    OAC_V5_NEGOTIATE_REQUEST negotiate{};
    negotiate.Header.Version = OAC_V5_VERSION;
    negotiate.Header.Size = static_cast<ULONG>(sizeof(negotiate));
    negotiate.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    negotiate.MinimumVersion = OAC_V5_VERSION;
    negotiate.MaximumVersion = OAC_V5_VERSION;
    if (!MakeRequestId(negotiate.Header.RequestId))
        return ERROR_GEN_FAILURE;

    OAC_V5_NEGOTIATE_RESPONSE negotiated{};
    DWORD returned = 0;
    if (!DeviceIoControl(
            candidate.get(),
            IOCTL_OAC_V5_NEGOTIATE,
            &negotiate,
            static_cast<DWORD>(sizeof(negotiate)),
            &negotiated,
            static_cast<DWORD>(sizeof(negotiated)),
            &returned,
            nullptr))
        return GetLastError();

    constexpr ULONG requiredProtocol = OAC_V5_PROTOCOL_STRICT_LENGTHS;
    constexpr ULONG requiredCapabilities =
        OAC_V5_CAP_SESSION_CONTROL | OAC_V5_CAP_LAUNCH_TICKET;
    if (OacV5ValidateNegotiateResponse(&negotiated, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &negotiate.Header, &negotiated.Header) != OAC_V5_VALID ||
        negotiated.Header.Status != 0 ||
        negotiated.Header.Reason != OAC_V5_REASON_NONE ||
        negotiated.Header.Flags != 0 ||
        (negotiated.Capabilities & requiredCapabilities) !=
            requiredCapabilities ||
        (negotiated.ProtocolFlags & requiredProtocol) != requiredProtocol)
        return ERROR_REVISION_MISMATCH;

    failureStage = OAC_SERVICE_STAGE_DRIVER_CLAIM;
    OAC_V5_CLAIM_REQUEST claim{};
    claim.Header.Version = OAC_V5_VERSION;
    claim.Header.Size = static_cast<ULONG>(sizeof(claim));
    claim.Header.MessageType = OAC_V5_MESSAGE_CLAIM_SESSION;
    claim.Mode = OAC_V5_SESSION_PRODUCTION;
    if (!MakeRequestId(claim.Header.RequestId)) return ERROR_GEN_FAILURE;

    OAC_V5_CLAIM_RESPONSE claimed{};
    returned = 0;
    if (!DeviceIoControl(
            candidate.get(),
            IOCTL_OAC_V5_CLAIM_SESSION,
            &claim,
            static_cast<DWORD>(sizeof(claim)),
            &claimed,
            static_cast<DWORD>(sizeof(claimed)),
            &returned,
            nullptr))
        return GetLastError();

    if (OacV5ValidateClaimResponse(&claimed, returned) != OAC_V5_VALID ||
        claimed.Header.MessageType != OAC_V5_MESSAGE_CLAIM_SESSION ||
        claimed.Header.RequestId != claim.Header.RequestId ||
        claimed.Header.Status != 0 ||
        claimed.Header.Reason != OAC_V5_REASON_NONE ||
        claimed.Header.Flags != 0 ||
        (claimed.Capabilities & requiredCapabilities) !=
            requiredCapabilities ||
        (claimed.Capabilities & ~negotiated.Capabilities) != 0)
        return ERROR_ACCESS_DENIED;

    failureStage = OAC_SERVICE_STAGE_DRIVER_STATUS;
    OAC_V5_STATUS_REQUEST statusRequest{};
    statusRequest.Header.Version = OAC_V5_VERSION;
    statusRequest.Header.Size = static_cast<ULONG>(sizeof(statusRequest));
    statusRequest.Header.MessageType = OAC_V5_MESSAGE_GET_STATUS;
    statusRequest.Header.SessionId = claimed.Header.SessionId;
    statusRequest.Header.Generation = claimed.Header.Generation;
    if (!MakeRequestId(statusRequest.Header.RequestId)) return ERROR_GEN_FAILURE;

    OAC_V5_STATUS_RESPONSE status{};
    returned = 0;
    if (!DeviceIoControl(
            candidate.get(),
            IOCTL_OAC_V5_GET_STATUS,
            &statusRequest,
            static_cast<DWORD>(sizeof(statusRequest)),
            &status,
            static_cast<DWORD>(sizeof(status)),
            &returned,
            nullptr))
        return GetLastError();

    if (OacV5ValidateStatusResponse(&status, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &statusRequest.Header, &status.Header) != OAC_V5_VALID ||
        status.Header.Status != 0 ||
        status.Header.Reason != OAC_V5_REASON_NONE ||
        status.Header.Flags != 0 ||
        status.State != OAC_V5_SESSION_CLAIMED ||
        status.Capabilities != claimed.Capabilities ||
        status.ConfigurationFlags != 0 ||
        status.RevokeReason != OAC_V5_REVOKE_NONE ||
        status.ServiceProcessId != GetCurrentProcessId() ||
        status.TargetProcessId != 0)
        return ERROR_INVALID_STATE;

    driver = candidate.release();
    version = negotiated.SelectedVersion;
    capabilities = status.Capabilities;
    sessionId = claimed.Header.SessionId;
    generation = claimed.Header.Generation;
    failureStage = OAC_SERVICE_STAGE_NONE;
    return ERROR_SUCCESS;
}
} // namespace

ServiceHost::ServiceHost(HANDLE stopEvent) noexcept
    : stopEvent_(stopEvent), fatalEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
}

ServiceHost::~ServiceHost()
{
    Stop();
    if (fatalEvent_ != nullptr) CloseHandle(fatalEvent_);
}

DWORD ServiceHost::Start(OAC_SERVICE_FAILURE_STAGE& failureStage) noexcept
{
    failureStage = OAC_SERVICE_STAGE_BOOTSTRAP;
    try
    {
        if (stopEvent_ == nullptr || fatalEvent_ == nullptr)
            return ERROR_NOT_ENOUGH_MEMORY;
        if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0)
            return ERROR_OPERATION_ABORTED;

        failureStage = OAC_SERVICE_STAGE_IDENTITY;
        DWORD error = VerifyServiceIdentity();
        if (error != ERROR_SUCCESS) return error;
        if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0)
            return ERROR_OPERATION_ABORTED;

        error = OpenAndClaimDriver(
            driver_,
            driverVersion_,
            driverCapabilities_,
            driverSessionId_,
            driverSessionGeneration_,
            failureStage);
        if (error != ERROR_SUCCESS) return error;
        if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0)
            return ERROR_OPERATION_ABORTED;

        failureStage = OAC_SERVICE_STAGE_PIPE_CREATE;
        firstPipe_ = CreateControlPipe(true, error);
        if (firstPipe_ == INVALID_HANDLE_VALUE) return error;

        failureStage = OAC_SERVICE_STAGE_PIPE_THREAD;
        pipeThread_ = CreateThread(nullptr, 0, PipeThreadEntry, this, 0, nullptr);
        if (pipeThread_ == nullptr) return GetLastError();
        failureStage = OAC_SERVICE_STAGE_NONE;
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

DWORD ServiceHost::Wait() const noexcept
{
    HANDLE waits[] = {stopEvent_, fatalEvent_};
    const DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (wait == WAIT_OBJECT_0) return ERROR_SUCCESS;
    if (wait == WAIT_OBJECT_0 + 1)
        return static_cast<DWORD>(InterlockedCompareExchange(
            const_cast<volatile LONG*>(&fatalError_),
            ERROR_SUCCESS,
            ERROR_SUCCESS));
    const DWORD error = GetLastError();
    return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error;
}

void ServiceHost::Stop() noexcept
{
    if (InterlockedCompareExchange(&stopped_, TRUE, FALSE) != FALSE) return;
    if (stopEvent_ != nullptr) SetEvent(stopEvent_);

    if (pipeThread_ != nullptr)
    {
        (void)WaitForSingleObject(pipeThread_, INFINITE);
        CloseHandle(pipeThread_);
        pipeThread_ = nullptr;
    }
    if (firstPipe_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(firstPipe_);
        firstPipe_ = INVALID_HANDLE_VALUE;
    }
    if (driver_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(driver_);
        driver_ = INVALID_HANDLE_VALUE;
    }
}

void ServiceHost::SetFatalError(DWORD error) noexcept
{
    if (error == ERROR_SUCCESS) error = ERROR_GEN_FAILURE;
    (void)InterlockedCompareExchange(
        &fatalError_,
        static_cast<LONG>(error),
        ERROR_SUCCESS);
    if (fatalEvent_ != nullptr) SetEvent(fatalEvent_);
}

DWORD WINAPI ServiceHost::PipeThreadEntry(void* context) noexcept
{
    auto* host = static_cast<ServiceHost*>(context);
    const DWORD error = host->PipeLoop();
    if (error != ERROR_SUCCESS && error != ERROR_OPERATION_ABORTED)
        host->SetFatalError(error);
    return error;
}

DWORD ServiceHost::PipeLoop() noexcept
{
    HANDLE pipe = firstPipe_;
    firstPipe_ = INVALID_HANDLE_VALUE;
    for (;;)
    {
        if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0)
        {
            CloseHandle(pipe);
            return ERROR_OPERATION_ABORTED;
        }

        DWORD error = ConnectClient(pipe, stopEvent_);
        if (error == ERROR_OPERATION_ABORTED)
        {
            CloseHandle(pipe);
            return error;
        }
        if (error != ERROR_SUCCESS)
        {
            CloseHandle(pipe);
            return error;
        }

        std::array<std::byte, OAC_IPC_MAX_MESSAGE_SIZE> buffer{};
        DWORD bytesRead = 0;
        error = ReadMessage(
            pipe,
            stopEvent_,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            bytesRead);
        DWORD fatalAfterResponse = ERROR_SUCCESS;
        if (error == ERROR_SUCCESS && bytesRead >= sizeof(OAC_IPC_HEADER))
        {
            OAC_IPC_HEADER header{};
            CopyMemory(&header, buffer.data(), sizeof(header));
            if (header.Type == OAC_IPC_TYPE_LAUNCH_REQUEST &&
                bytesRead == sizeof(OAC_IPC_LAUNCH_REQUEST))
            {
                OAC_IPC_LAUNCH_REQUEST request{};
                CopyMemory(&request, buffer.data(), sizeof(request));
                if (!OacIpcValidateLaunchRequest(&request, bytesRead))
                    goto CompleteConnection;

                ClientIdentity client;
                const DWORD authorization = AuthorizeClient(pipe, client);
                if (client.revertFailed)
                {
                    CloseHandle(pipe);
                    return authorization;
                }

                OAC_IPC_LAUNCH_RESPONSE response{};
                response.Header.Version = OAC_IPC_VERSION;
                response.Header.Size = static_cast<uint32_t>(sizeof(response));
                response.Header.Type = OAC_IPC_TYPE_LAUNCH_RESPONSE;
                response.Header.RequestId = request.Header.RequestId;
                response.Win32Error = authorization;
                response.FailureStage = OAC_IPC_LAUNCH_STAGE_AUTHORIZE_CLIENT;
                if (authorization == ERROR_SUCCESS)
                {
                    bool driverSessionChanged = false;
                    DWORD targetProcessId = 0;
                    try
                    {
                        response.Win32Error = LaunchTarget(
                            pipe,
                            stopEvent_,
                            driver_,
                            driverSessionId_,
                            driverSessionGeneration_,
                            request,
                            client,
                            targetProcessId,
                            driverSessionChanged,
                            response.FailureStage,
                            response.FailureDetail);
                    }
                    catch (const std::bad_alloc&)
                    {
                        response.Win32Error = ERROR_NOT_ENOUGH_MEMORY;
                    }
                    catch (...)
                    {
                        response.Win32Error = ERROR_UNHANDLED_EXCEPTION;
                    }
                    if (client.revertFailed)
                    {
                        CloseHandle(pipe);
                        return response.Win32Error;
                    }
                    if (response.Win32Error == ERROR_SUCCESS)
                    {
                        response.LaunchFlags = OAC_IPC_LAUNCH_CONFIRMED |
                            OAC_IPC_LAUNCH_RESUMED;
                        response.ServiceProcessId = GetCurrentProcessId();
                        response.ClientProcessId = client.processId;
                        response.ClientSessionId = client.sessionId;
                        response.TargetProcessId = targetProcessId;
                    }
                    else if (driverSessionChanged)
                    {
                        fatalAfterResponse = response.Win32Error;
                    }
                }
                error = WriteMessage(
                    pipe,
                    stopEvent_,
                    &response,
                    static_cast<DWORD>(sizeof(response)));
            }
            else if (bytesRead == sizeof(OAC_IPC_REQUEST))
            {
                OAC_IPC_REQUEST request{};
                CopyMemory(&request, buffer.data(), sizeof(request));
                if (ValidRequest(request, bytesRead))
                {
                    ClientIdentity client;
                    const DWORD authorization = AuthorizeClient(pipe, client);
                    if (client.revertFailed)
                    {
                        CloseHandle(pipe);
                        return authorization;
                    }

                    OAC_IPC_RESPONSE response{};
                    response.Header.Version = OAC_IPC_VERSION;
                    response.Header.Size =
                        static_cast<uint32_t>(sizeof(response));
                    response.Header.Type =
                        request.Header.Type == OAC_IPC_TYPE_HELLO_REQUEST
                        ? OAC_IPC_TYPE_HELLO_RESPONSE
                        : OAC_IPC_TYPE_STATUS_RESPONSE;
                    response.Header.RequestId = request.Header.RequestId;
                    response.Win32Error = authorization;
                    if (authorization == ERROR_SUCCESS)
                    {
                        OAC_V5_STATUS_RESPONSE driverStatus{};
                        response.Win32Error = ReadDriverStatus(
                            driver_,
                            driverSessionId_,
                            driverSessionGeneration_,
                            driverStatus);
                        if (response.Win32Error == ERROR_SUCCESS)
                        {
                            response.StatusFlags = OAC_IPC_STATUS_DRIVER_READY;
                            if (SessionHasControl(driverStatus.State))
                            {
                                response.StatusFlags |=
                                    OAC_IPC_STATUS_SESSION_CLAIMED;
                            }
                            response.ServiceProcessId = GetCurrentProcessId();
                            response.ClientProcessId = client.processId;
                            response.ClientSessionId = client.sessionId;
                            response.DriverProtocolVersion = driverVersion_;
                            response.DriverCapabilities = driverCapabilities_;
                        }
                        else
                        {
                            fatalAfterResponse = response.Win32Error;
                        }
                    }
                    error = WriteMessage(
                        pipe,
                        stopEvent_,
                        &response,
                        static_cast<DWORD>(sizeof(response)));
                }
            }
        }

CompleteConnection:
        if (error == ERROR_OPERATION_ABORTED)
        {
            (void)DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            return error;
        }
        if (fatalAfterResponse != ERROR_SUCCESS)
        {
            (void)DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            return fatalAfterResponse;
        }

        HANDLE nextPipe = CreateControlPipe(false, error);
        if (nextPipe == INVALID_HANDLE_VALUE)
        {
            (void)DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            return error;
        }
        (void)DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        pipe = nextPipe;
    }
}
