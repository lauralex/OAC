#include "endpoint_preflight.hpp"

#include <bcrypt.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <limits>
#include <new>
#include <set>
#include <sstream>
#include <utility>

#include "..\shared\oac_driver_trust.hpp"
#include "..\shared\protocol\oac_validate.h"

namespace
{
constexpr ULONG kMaximumKernelModules = 4096;
using SnapshotStorage = std::array<std::byte,
    offsetof(OAC_SNAPSHOT_RESPONSE, Records) +
    OAC_SNAPSHOT_MAX_RECORDS_PER_PAGE * sizeof(OAC_SNAPSHOT_RECORD)>;

bool MakeRequestId(ULONGLONG& requestId) noexcept
{
    requestId = 0;
    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(&requestId),
        static_cast<ULONG>(sizeof(requestId)),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) && requestId != 0;
}

bool InitializeRequest(
    OAC_V5_REQUEST_HEADER& header,
    ULONG size,
    ULONG messageType,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation) noexcept
{
    header = {};
    header.Version = OAC_V5_VERSION;
    header.Size = size;
    header.SessionId = sessionId;
    header.Generation = generation;
    header.MessageType = messageType;
    return MakeRequestId(header.RequestId);
}

DWORD CallSnapshot(
    HANDLE driver,
    OAC_SNAPSHOT_REQUEST& request,
    SnapshotStorage& storage,
    const OAC_SNAPSHOT_RESPONSE*& response) noexcept
{
    storage = {};
    response = reinterpret_cast<const OAC_SNAPSHOT_RESPONSE*>(storage.data());
    const DWORD outputSize = request.Operation == OAC_SNAPSHOT_OPERATION_CLOSE
        ? static_cast<DWORD>(offsetof(OAC_SNAPSHOT_RESPONSE, Records))
        : static_cast<DWORD>(storage.size());
    DWORD returned = 0;
    if (!DeviceIoControl(
            driver,
            IOCTL_OAC_MANAGE_SNAPSHOT,
            &request,
            static_cast<DWORD>(sizeof(request)),
            storage.data(),
            outputSize,
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    if (OacValidateSnapshotResponse(response, returned) != OAC_V5_VALID ||
        OacValidateSnapshotCorrelation(&request, response) != OAC_V5_VALID ||
        response->Header.Status != 0 ||
        response->Header.Reason != OAC_V5_REASON_NONE)
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

void InitializeSnapshotRequest(
    OAC_SNAPSHOT_REQUEST& request,
    ULONG operation,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    const OAC_SNAPSHOT_ID& snapshotId,
    ULONGLONG cursorGeneration,
    ULONGLONG cursor) noexcept
{
    request = {};
    if (!InitializeRequest(
            request.Header,
            static_cast<ULONG>(sizeof(request)),
            OAC_MESSAGE_MANAGE_SNAPSHOT,
            sessionId,
            generation))
    {
        return;
    }
    request.Operation = operation;
    request.SnapshotType = OAC_SNAPSHOT_TYPE_KERNEL_MODULES;
    request.SnapshotId = snapshotId;
    request.CursorGeneration = cursorGeneration;
    request.Cursor = cursor;
    request.MaximumRecords = operation == OAC_SNAPSHOT_OPERATION_CLOSE
        ? 0
        : OAC_SNAPSHOT_MAX_RECORDS_PER_PAGE;
}

bool SameSnapshot(
    const OAC_SNAPSHOT_RESPONSE& first,
    const OAC_SNAPSHOT_RESPONSE& next) noexcept
{
    return OacSnapshotIdEqual(&first.SnapshotId, &next.SnapshotId) &&
        first.ScanId == next.ScanId &&
        first.CreatedTimestamp100ns == next.CreatedTimestamp100ns &&
        first.ExpirationInterruptTime100ns ==
            next.ExpirationInterruptTime100ns &&
        first.CursorGeneration == next.CursorGeneration &&
        first.SnapshotType == next.SnapshotType &&
        first.TotalItems == next.TotalItems &&
        first.AvailableItems == next.AvailableItems &&
        first.Truncated == next.Truncated;
}

DWORD ReadKernelModules(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    std::vector<OAC_SNAPSHOT_RECORD>& records,
    OAC_V5_SCAN_ID& snapshotScanId)
{
    records.clear();
    snapshotScanId = 0;
    OAC_SNAPSHOT_REQUEST request{};
    const OAC_SNAPSHOT_ID emptyId{};
    InitializeSnapshotRequest(
        request,
        OAC_SNAPSHOT_OPERATION_OPEN,
        sessionId,
        generation,
        emptyId,
        0,
        0);
    if (request.Header.RequestId == 0) return ERROR_GEN_FAILURE;

    SnapshotStorage storage{};
    const OAC_SNAPSHOT_RESPONSE* response = nullptr;
    DWORD error = CallSnapshot(driver, request, storage, response);
    if (error != ERROR_SUCCESS) return error;

    const OAC_SNAPSHOT_RESPONSE first = *response;
    const OAC_SNAPSHOT_ID snapshotId = response->SnapshotId;
    const ULONGLONG cursorGeneration = response->CursorGeneration;
    const auto closeSnapshot = [&]() noexcept -> DWORD
    {
        OAC_SNAPSHOT_REQUEST close{};
        InitializeSnapshotRequest(
            close,
            OAC_SNAPSHOT_OPERATION_CLOSE,
            sessionId,
            generation,
            snapshotId,
            cursorGeneration,
            0);
        if (close.Header.RequestId == 0) return ERROR_GEN_FAILURE;
        SnapshotStorage closeStorage{};
        const OAC_SNAPSHOT_RESPONSE* closed = nullptr;
        return CallSnapshot(driver, close, closeStorage, closed);
    };

    if (response->State != OAC_SNAPSHOT_STATE_READY ||
        response->FailureStatus != 0 || response->Truncated != 0 ||
        response->TotalItems == 0 ||
        response->TotalItems != response->AvailableItems ||
        response->TotalItems > kMaximumKernelModules)
    {
        (void)closeSnapshot();
        return ERROR_INVALID_DATA;
    }

    try
    {
        records.reserve(response->TotalItems);
        for (;;)
        {
            if (!SameSnapshot(first, *response) ||
                response->Cursor != records.size())
            {
                error = ERROR_INVALID_DATA;
                break;
            }
            records.insert(
                records.end(),
                response->Records,
                response->Records + response->RecordCount);
            if (response->NextCursor == response->AvailableItems) break;

            InitializeSnapshotRequest(
                request,
                OAC_SNAPSHOT_OPERATION_READ,
                sessionId,
                generation,
                snapshotId,
                cursorGeneration,
                response->NextCursor);
            if (request.Header.RequestId == 0)
            {
                error = ERROR_GEN_FAILURE;
                break;
            }
            error = CallSnapshot(driver, request, storage, response);
            if (error != ERROR_SUCCESS) break;
        }
    }
    catch (const std::bad_alloc&)
    {
        error = ERROR_NOT_ENOUGH_MEMORY;
    }
    const DWORD closeError = closeSnapshot();
    if (error != ERROR_SUCCESS) return error;
    if (closeError != ERROR_SUCCESS) return closeError;
    if (records.size() != first.TotalItems) return ERROR_INVALID_DATA;
    snapshotScanId = first.ScanId;
    return ERROR_SUCCESS;
}

std::wstring DriverObservationText(
    std::wstring_view reportedPath,
    const oac::DriverTrustReport& trust,
    DWORD evaluationError)
{
    std::wostringstream message;
    if (evaluationError != ERROR_SUCCESS)
    {
        message << L"Loaded kernel module identity could not be verified: "
            << reportedPath << L"; error=" << evaluationError;
        return message.str();
    }
    if (trust.DeniedHash)
        message << L"Loaded kernel module matches the denied hash policy: ";
    else if (trust.DeniedFamily)
        message << L"Loaded kernel module matches the denied family policy: ";
    else if (trust.ReviewFamily)
        message << L"Loaded kernel module requires explicit approval: ";
    else
        message << L"Loaded kernel module failed trust validation: ";
    message << trust.Path << L"; trust=0x" << std::hex
        << static_cast<ULONG>(trust.TrustStatus)
        << L"; authenticode-sha256=";
    if (trust.AuthenticodeSha256.empty()) message << L"unavailable";
    else
    {
        message << std::wstring(
            trust.AuthenticodeSha256.begin(),
            trust.AuthenticodeSha256.end());
    }
    return message.str();
}

DWORD EvaluateKernelModules(
    const std::vector<OAC_SNAPSHOT_RECORD>& records,
    std::vector<oac::EndpointObservation>& observations)
{
    std::set<ULONGLONG> addresses;
    for (const auto& record : records)
    {
        if (!addresses.insert(record.Address).second)
            return ERROR_INVALID_DATA;
        const std::wstring_view reportedPath(
            record.Name, record.NameLength);
        oac::DriverTrustReport trust{};
        const DWORD error = oac::EvaluateDriverTrust(reportedPath, trust);
        if (error == ERROR_SUCCESS && oac::DriverTrustAccepted(trust))
        {
            continue;
        }

        oac::EndpointObservation observation{};
        if (error == ERROR_SUCCESS && trust.DeniedHash)
            observation.RuleId = OAC_V5_RULE_DRIVER_HASH_DENIED;
        else if (error == ERROR_SUCCESS && trust.DeniedFamily)
            observation.RuleId = OAC_V5_RULE_DRIVER_FAMILY_DENIED;
        else if (error == ERROR_SUCCESS && trust.ReviewFamily)
            observation.RuleId = OAC_V5_RULE_DRIVER_REVIEW_REQUIRED;
        else
            observation.RuleId = OAC_V5_RULE_DRIVER_TRUST_FAILED;
        observation.Severity = observation.RuleId ==
                OAC_V5_RULE_DRIVER_HASH_DENIED ||
                observation.RuleId == OAC_V5_RULE_DRIVER_FAMILY_DENIED
            ? OAC_V5_OBSERVATION_CRITICAL
            : OAC_V5_OBSERVATION_HIGH;
        observation.Category = OAC_V5_CATEGORY_DRIVER;
        observation.EvidenceFlags = OAC_V5_EVIDENCE_SERVICE_SOURCE;
        if (error == ERROR_SUCCESS)
            observation.EvidenceFlags |= OAC_V5_EVIDENCE_SIGNATURE_CHECKED;
        observation.Text = DriverObservationText(
            reportedPath, trust, error);
        observations.push_back(std::move(observation));
    }
    return ERROR_SUCCESS;
}
} // namespace

namespace oac
{
DWORD CollectEndpointPreflight(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    EndpointPreflightResult& result) noexcept
{
    result = {};
    if (driver == nullptr || driver == INVALID_HANDLE_VALUE ||
        OacV5SessionIdIsZero(&sessionId) || generation == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    try
    {
        DWORD error = ConfigureEndpointMonitoring(
            driver, sessionId, generation);
        if (error != ERROR_SUCCESS) return error;

        OAC_ENDPOINT_SCAN_REQUEST request{};
        if (!InitializeRequest(
                request.Header,
                static_cast<ULONG>(sizeof(request)),
                OAC_V5_MESSAGE_RUN_SCAN,
                sessionId,
                generation))
        {
            return ERROR_GEN_FAILURE;
        }
        request.RequestedFlags = OAC_ENDPOINT_SCAN_REQUIRED_FLAGS;
        DWORD returned = 0;
        if (!DeviceIoControl(
                driver,
                IOCTL_OAC_V5_RUN_SCAN,
                &request,
                static_cast<DWORD>(sizeof(request)),
                &result.Scan,
                static_cast<DWORD>(sizeof(result.Scan)),
                &returned,
                nullptr))
        {
            return GetLastError();
        }
        if (OacValidateEndpointScanResponse(
                &result.Scan, returned) != OAC_V5_VALID ||
            OacV5ValidateCorrelation(
                &request.Header,
                &result.Scan.Header) != OAC_V5_VALID ||
            result.Scan.Header.Status != 0 ||
            result.Scan.Header.Reason != OAC_V5_REASON_NONE ||
            result.Scan.Header.Flags != 0)
        {
            return ERROR_INVALID_DATA;
        }
        if (result.Scan.State != OAC_ENDPOINT_SCAN_COMPLETE)
            return ERROR_SUCCESS;

        std::vector<OAC_SNAPSHOT_RECORD> modules;
        error = ReadKernelModules(
            driver,
            sessionId,
            generation,
            modules,
            result.ModuleSnapshotScanId);
        if (error != ERROR_SUCCESS) return error;
        if (modules.size() > (std::numeric_limits<ULONG>::max)())
            return ERROR_ARITHMETIC_OVERFLOW;
        result.ModulesInspected = static_cast<ULONG>(modules.size());
        return EvaluateKernelModules(modules, result.Observations);
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

DWORD ConfigureEndpointMonitoring(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation) noexcept
{
    if (driver == nullptr || driver == INVALID_HANDLE_VALUE ||
        OacV5SessionIdIsZero(&sessionId) || generation == 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    OAC_ENDPOINT_CONFIG_REQUEST request{};
    if (!InitializeRequest(
            request.Header,
            static_cast<ULONG>(sizeof(request)),
            OAC_V5_MESSAGE_SET_CONFIG,
            sessionId,
            generation))
    {
        return ERROR_GEN_FAILURE;
    }
    request.ConfigurationFlags = OAC_V5_CONFIG_FLAGS;
    OAC_ENDPOINT_CONFIG_RESPONSE response{};
    DWORD returned = 0;
    if (!DeviceIoControl(
            driver,
            IOCTL_OAC_V5_SET_CONFIG,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            nullptr))
    {
        return GetLastError();
    }
    if (OacValidateEndpointConfigResponse(
            &response, returned) != OAC_V5_VALID ||
        OacV5ValidateCorrelation(
            &request.Header, &response.Header) != OAC_V5_VALID ||
        response.Header.Status != 0 ||
        response.Header.Reason != OAC_V5_REASON_NONE ||
        response.Header.Flags != 0 ||
        response.ConfigurationFlags != OAC_V5_CONFIG_FLAGS)
    {
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}
} // namespace oac
