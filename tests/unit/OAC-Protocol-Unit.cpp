#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iterator>
#include <set>
#include <string>
#include <type_traits>

#include "../../shared/oac_protocol.h"
#include "../../shared/oac_backend.h"
#include "../../shared/oac_ipc.h"
#include "../../shared/oac_lease.h"
#include "../../shared/oac_manifest.h"
#include "../../shared/oac_policy.h"
#include "../../shared/oac_signed_policy.h"
#include "../../shared/oac_thread_suspension.hpp"
#include "../../shared/protocol/oac_v5.h"
#include "../../shared/protocol/oac_validate.h"
#include "../../shared/protocol/oac_test.h"
#include "../../OAC-Service/backend.hpp"
#include "../../OAC-Service/target_scanner.hpp"

extern "C" int OacV5CProbe(void);

static_assert(std::is_standard_layout_v<OAC_V5_REQUEST_HEADER>);
static_assert(std::is_trivially_copyable_v<OAC_V5_EVENT_RECORD>);
static_assert(offsetof(OAC_V5_STATUS_RESPONSE, ServiceProcessId) == 72);
static_assert(offsetof(OAC_V5_REQUEST_HEADER, MessageType) == 44);
static_assert(offsetof(OAC_V5_RESPONSE_HEADER, MessageType) == 52);
static_assert(offsetof(OAC_V5_EVENT_RECORD, PolicySeverity) == 20);
static_assert(offsetof(OAC_V5_EVENT_RECORD, Reserved) == 36);
static_assert(std::is_standard_layout_v<OAC_ARM_LAUNCH_REQUEST>);
static_assert(std::is_trivially_copyable_v<OAC_CONFIRM_TARGET_REQUEST>);
static_assert(sizeof(OAC_ARM_LAUNCH_REQUEST) == 2144);
static_assert(OAC_MANIFEST_HASH_SIZE == OAC_V5_MANIFEST_DIGEST_SIZE);
static_assert(offsetof(OAC_ARM_LAUNCH_REQUEST, ManifestSha256) == 64);
static_assert(offsetof(OAC_ARM_LAUNCH_REQUEST, CanonicalNtPath) == 96);
static_assert(offsetof(OAC_ARM_LAUNCH_REQUEST,
    CanonicalDosDevicePath) == 1120);
static_assert(sizeof(OAC_ARM_LAUNCH_RESPONSE) == 88);
static_assert(sizeof(OAC_CANCEL_LAUNCH_REQUEST) == 64);
static_assert(sizeof(OAC_CANCEL_LAUNCH_RESPONSE) == 64);
static_assert(sizeof(OAC_CONFIRM_TARGET_REQUEST) == 72);
static_assert(sizeof(OAC_CONFIRM_TARGET_RESPONSE) == 72);
static_assert(sizeof(OAC_REVOKE_SESSION_REQUEST) == 56);
static_assert(sizeof(OAC_REVOKE_SESSION_RESPONSE) == 80);
static_assert(sizeof(OAC_EVIDENCE_READ_REQUEST) == 80);
static_assert(offsetof(OAC_EVIDENCE_READ_RESPONSE, Records) == 136);
static_assert(sizeof(OAC_SNAPSHOT_RECORD) == 560);
static_assert(sizeof(OAC_SNAPSHOT_REQUEST) == 96);
static_assert(offsetof(OAC_SNAPSHOT_RESPONSE, Records) == 152);
static_assert(std::is_standard_layout_v<OAC_IPC_LAUNCH_REQUEST>);
static_assert(sizeof(OAC_IPC_SCAN_METRICS) == 184);
static_assert(offsetof(OAC_IPC_SCAN_METRICS, State) == 168);
static_assert(sizeof(OAC_IPC_BACKEND_STATUS) == 32);
static_assert(sizeof(OAC_IPC_RESPONSE) == 288);
static_assert(sizeof(OAC_IPC_LAUNCH_REQUEST) == 1056);
static_assert(offsetof(OAC_IPC_LAUNCH_REQUEST, ExecutablePath) == 32);
static_assert(sizeof(OAC_IPC_LAUNCH_RESPONSE) == 56);
static_assert(offsetof(OAC_IPC_LAUNCH_RESPONSE, FailureStage) == 48);
static_assert(offsetof(OAC_IPC_LAUNCH_RESPONSE, FailureDetail) == 52);
static_assert(std::is_standard_layout_v<OAC_POLICY_SIGNER_CLASSIFICATION>);
static_assert(std::is_trivially_copyable_v<OAC_POLICY_DECISION>);
static_assert(sizeof(OAC_POLICY_SIGNER_CLASSIFICATION) == 64);
static_assert(sizeof(OAC_POLICY_RULE) == 56);
static_assert(sizeof(OAC_POLICY_DECISION) == 16);
static_assert(std::is_standard_layout_v<OAC_GAME_MANIFEST>);
static_assert(std::is_trivially_copyable_v<OAC_MANIFEST_ROLLBACK_STATE>);
static_assert(sizeof(OAC_GAME_MANIFEST) == 512);
static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableSha256) == 120);
static_assert(offsetof(OAC_GAME_MANIFEST, ExecutableName) == 184);
static_assert(sizeof(OAC_MANIFEST_ROLLBACK_STATE) == 96);
static_assert(std::is_standard_layout_v<OAC_SIGNED_POLICY>);
static_assert(std::is_trivially_copyable_v<OAC_POLICY_CACHE_STATE>);
static_assert(sizeof(OAC_SIGNED_POLICY) == 1024);
static_assert(offsetof(OAC_SIGNED_POLICY, Rules) == 216);
static_assert(offsetof(OAC_SIGNED_POLICY, BackendLeaseMilliseconds) == 1000);
static_assert(sizeof(OAC_POLICY_CACHE_STATE) == 160);
static_assert(sizeof(OAC_BACKEND_REQUEST_HEADER) == 88);
static_assert(sizeof(OAC_BACKEND_OPEN_REQUEST) == 184);
static_assert(sizeof(OAC_BACKEND_OPEN_RESPONSE) == 144);
static_assert(sizeof(OAC_BACKEND_EVIDENCE_ITEM) == 584);

namespace
{
class TestLog
{
public:
    void Expect(const std::string& name, bool passed)
    {
        ++total_;
        if (passed)
        {
            ++passed_;
            std::cout << "[PASS] " << name << '\n';
        }
        else
        {
            std::cerr << "[FAIL] " << name << '\n';
        }
    }

    [[nodiscard]] int ExitCode() const
    {
        std::cout << "SUMMARY passed=" << passed_ << " total=" << total_ << '\n';
        return passed_ == total_ ? 0 : 1;
    }

private:
    unsigned total_ = 0;
    unsigned passed_ = 0;
};

void FillOpenHeader(
    OAC_V5_REQUEST_HEADER& header,
    ULONG size,
    OAC_V5_MESSAGE_TYPE messageType)
{
    header = {};
    header.Version = OAC_V5_VERSION;
    header.Size = size;
    header.RequestId = 0x1020304050607080ULL;
    header.MessageType = messageType;
}

void FillSessionHeader(
    OAC_V5_REQUEST_HEADER& header,
    ULONG size,
    OAC_V5_MESSAGE_TYPE messageType)
{
    FillOpenHeader(header, size, messageType);
    header.SessionId.High = 0x1122334455667788ULL;
    header.SessionId.Low = 0x8877665544332211ULL;
    header.Generation = 7;
}

void FillOpenHeader(
    OAC_V5_RESPONSE_HEADER& header,
    ULONG size,
    OAC_V5_MESSAGE_TYPE messageType)
{
    header = {};
    header.Version = OAC_V5_VERSION;
    header.Size = size;
    header.RequestId = 0x1020304050607080ULL;
    header.Status = 0;
    header.Reason = OAC_V5_REASON_NONE;
    header.MessageType = messageType;
}

void FillSessionHeader(
    OAC_V5_RESPONSE_HEADER& header,
    ULONG size,
    OAC_V5_MESSAGE_TYPE messageType)
{
    FillOpenHeader(header, size, messageType);
    header.SessionId.High = 0x1122334455667788ULL;
    header.SessionId.Low = 0x8877665544332211ULL;
    header.Generation = 7;
}

OAC_V5_NEGOTIATE_REQUEST ValidNegotiateRequest()
{
    OAC_V5_NEGOTIATE_REQUEST request{};
    FillOpenHeader(
        request.Header,
        sizeof(request),
        OAC_V5_MESSAGE_NEGOTIATE);
    request.MinimumVersion = OAC_V5_VERSION;
    request.MaximumVersion = OAC_V5_VERSION;
    return request;
}

OAC_V5_CLAIM_REQUEST ValidClaimRequest()
{
    OAC_V5_CLAIM_REQUEST request{};
    FillOpenHeader(
        request.Header,
        sizeof(request),
        OAC_V5_MESSAGE_CLAIM_SESSION);
    request.Mode = OAC_V5_SESSION_PRODUCTION;
    std::fill(
        std::begin(request.BackendBindingSha256),
        std::end(request.BackendBindingSha256),
        UCHAR{0xA5});
    return request;
}

OAC_V5_STATUS_REQUEST ValidStatusRequest()
{
    OAC_V5_STATUS_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_V5_MESSAGE_GET_STATUS);
    return request;
}

OAC_REVOKE_SESSION_REQUEST ValidRevokeRequest()
{
    OAC_REVOKE_SESSION_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_V5_MESSAGE_REVOKE_SESSION);
    request.RevokeReason = OAC_V5_REVOKE_REQUESTED;
    return request;
}

OAC_V5_NEGOTIATE_RESPONSE ValidNegotiateResponse()
{
    OAC_V5_NEGOTIATE_RESPONSE response{};
    FillOpenHeader(
        response.Header,
        sizeof(response),
        OAC_V5_MESSAGE_NEGOTIATE);
    response.MinimumVersion = OAC_V5_VERSION;
    response.SelectedVersion = OAC_V5_VERSION;
    response.MaximumVersion = OAC_V5_VERSION;
    response.Capabilities = OAC_V5_CAP_SESSION_CONTROL |
        OAC_V5_CAP_TYPED_EVENTS;
    response.MaximumInputSize = OAC_V5_MAX_INPUT_SIZE;
    response.MaximumOutputSize = OAC_V5_MAX_OUTPUT_SIZE;
    response.MaximumEventCount = OAC_EVIDENCE_MAX_RECORDS_PER_PAGE;
    response.ProtocolFlags = OAC_V5_PROTOCOL_STRICT_LENGTHS |
        OAC_V5_PROTOCOL_TYPED_EVENTS;
    return response;
}

OAC_V5_CLAIM_RESPONSE ValidClaimResponse()
{
    OAC_V5_CLAIM_RESPONSE response{};
    FillSessionHeader(
        response.Header,
        sizeof(response),
        OAC_V5_MESSAGE_CLAIM_SESSION);
    response.State = OAC_V5_SESSION_CLAIMED;
    response.Capabilities = OAC_V5_CAP_SESSION_CONTROL;
    return response;
}

OAC_V5_STATUS_RESPONSE ValidStatusResponse()
{
    OAC_V5_STATUS_RESPONSE response{};
    FillSessionHeader(
        response.Header,
        sizeof(response),
        OAC_V5_MESSAGE_GET_STATUS);
    response.State = OAC_V5_SESSION_CLAIMED;
    response.Capabilities = OAC_V5_CAP_SESSION_CONTROL |
        OAC_V5_CAP_DRIVER_GATE;
    response.ConfigurationFlags = OAC_V5_CONFIG_DRIVER_GATE;
    response.RevokeReason = OAC_V5_REVOKE_NONE;
    response.ServiceProcessId = 100;
    response.SessionMode = OAC_V5_SESSION_PRODUCTION;
    std::fill(
        std::begin(response.BackendBindingSha256),
        std::end(response.BackendBindingSha256),
        UCHAR{0xA5});
    return response;
}

OAC_REVOKE_SESSION_RESPONSE ValidRevokeResponse()
{
    OAC_REVOKE_SESSION_RESPONSE response{};
    FillSessionHeader(
        response.Header,
        sizeof(response),
        OAC_V5_MESSAGE_REVOKE_SESSION);
    response.Header.Flags = OAC_V5_RESPONSE_REVOKED;
    response.State = OAC_V5_SESSION_REVOKED;
    response.RevokeReason = OAC_V5_REVOKE_REQUESTED;
    response.SessionLossSequence = 1;
    response.LastSessionLossReason = OAC_V5_REVOKE_REQUESTED;
    return response;
}

OAC_LAUNCH_ID ValidLaunchId()
{
    return {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
}

template <std::size_t Length>
void SetCanonicalPath(
    OAC_ARM_LAUNCH_REQUEST& request,
    const WCHAR (&path)[Length])
{
    static_assert(Length <= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS);
    std::memset(request.CanonicalNtPath, 0, sizeof(request.CanonicalNtPath));
    request.CanonicalNtPathLength = static_cast<ULONG>(Length - 1);
    std::memcpy(request.CanonicalNtPath, path, sizeof(path));
}

template <std::size_t Length>
void SetCanonicalDosDevicePath(
    OAC_ARM_LAUNCH_REQUEST& request,
    const WCHAR (&path)[Length])
{
    static_assert(Length <= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS);
    std::memset(
        request.CanonicalDosDevicePath,
        0,
        sizeof(request.CanonicalDosDevicePath));
    request.CanonicalDosDevicePathLength = static_cast<ULONG>(Length - 1);
    std::memcpy(request.CanonicalDosDevicePath, path, sizeof(path));
}

constexpr WCHAR kValidLaunchPath[] =
    L"\\Device\\HarddiskVolume3\\Games\\OAC.exe";
constexpr WCHAR kValidLaunchDosDevicePath[] = L"\\??\\C:\\Games\\OAC.exe";

OAC_ARM_LAUNCH_REQUEST ValidArmLaunchRequest()
{
    OAC_ARM_LAUNCH_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_MESSAGE_ARM_LAUNCH);
    request.TimeToLiveMilliseconds = 2000;
    for (size_t index = 0; index != sizeof(request.ManifestSha256); ++index)
        request.ManifestSha256[index] = static_cast<UCHAR>(index + 1);
    SetCanonicalPath(request, kValidLaunchPath);
    SetCanonicalDosDevicePath(request, kValidLaunchDosDevicePath);
    return request;
}

OAC_ARM_LAUNCH_RESPONSE ValidArmLaunchResponse()
{
    OAC_ARM_LAUNCH_RESPONSE response{};
    FillSessionHeader(
        response.Header,
        sizeof(response),
        OAC_MESSAGE_ARM_LAUNCH);
    response.LaunchId = ValidLaunchId();
    response.ExpirationInterruptTime100ns = 100000;
    response.State = OAC_V5_SESSION_LAUNCH_PENDING;
    return response;
}

OAC_CANCEL_LAUNCH_REQUEST ValidCancelLaunchRequest()
{
    OAC_CANCEL_LAUNCH_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_MESSAGE_CANCEL_LAUNCH);
    request.LaunchId = ValidLaunchId();
    return request;
}

OAC_CANCEL_LAUNCH_RESPONSE ValidCancelLaunchResponse()
{
    OAC_CANCEL_LAUNCH_RESPONSE response{};
    FillSessionHeader(
        response.Header,
        sizeof(response),
        OAC_MESSAGE_CANCEL_LAUNCH);
    response.Header.Flags = OAC_V5_RESPONSE_REVOKED;
    response.State = OAC_V5_SESSION_REVOKED;
    return response;
}

OAC_CONFIRM_TARGET_REQUEST ValidConfirmTargetRequest()
{
    OAC_CONFIRM_TARGET_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_MESSAGE_CONFIRM_TARGET);
    request.LaunchId = ValidLaunchId();
    request.TargetProcessHandle = 0x1234;
    return request;
}

OAC_CONFIRM_TARGET_RESPONSE ValidConfirmTargetResponse()
{
    OAC_CONFIRM_TARGET_RESPONSE response{};
    FillSessionHeader(
        response.Header,
        sizeof(response),
        OAC_MESSAGE_CONFIRM_TARGET);
    response.TargetProcessId = 1234;
    response.State = OAC_V5_SESSION_MONITORING;
    return response;
}

OAC_V5_EVENT_RECORD ValidEventRecord()
{
    OAC_V5_EVENT_RECORD record{};
    record.Version = OAC_V5_VERSION;
    record.Size = sizeof(record);
    record.RuleId = OAC_V5_RULE_DRIVER_GATE_TRIP;
    record.EventType = OAC_V5_EVENT_OBSERVATION;
    record.ObservationSeverity = OAC_V5_OBSERVATION_MEDIUM;
    record.PolicySeverity = OAC_V5_POLICY_NOT_EVALUATED;
    record.Confidence = OAC_V5_CONFIDENCE_HIGH;
    record.Category = OAC_V5_CATEGORY_DRIVER;
    record.PayloadType = OAC_V5_PAYLOAD_NONE;
    record.SessionId.High = 0x1122334455667788ULL;
    record.SessionId.Low = 0x8877665544332211ULL;
    record.Generation = 7;
    record.Sequence = 11;
    record.Timestamp100ns = 100;
    record.OccurrenceCount = 1;
    record.FirstOccurrence100ns = record.Timestamp100ns;
    record.LastOccurrence100ns = record.Timestamp100ns;
    record.EvidenceFlags = OAC_V5_EVIDENCE_KERNEL_SOURCE;
    return record;
}

OAC_EVIDENCE_READ_REQUEST ValidEvidenceRequest(ULONG channel)
{
    OAC_EVIDENCE_READ_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_MESSAGE_READ_EVIDENCE);
    request.Channel = channel;
    request.MaximumRecords = 2;
    return request;
}

OAC_SNAPSHOT_ID ValidSnapshotId()
{
    return {0x1111222233334444ULL, 0xaaaabbbbccccddddULL};
}

OAC_SNAPSHOT_RECORD ValidSnapshotRecord(ULONGLONG index)
{
    OAC_SNAPSHOT_RECORD record{};
    constexpr WCHAR name[] = L"\\SystemRoot\\System32\\ntoskrnl.exe";
    record.Version = OAC_V5_VERSION;
    record.Size = sizeof(record);
    record.RecordType = OAC_SNAPSHOT_RECORD_KERNEL_MODULE;
    record.Index = index;
    record.Address = 0xfffff80000000000ULL + index * 0x100000ULL;
    record.Length = 0x100000;
    record.NameLength = static_cast<ULONG>(std::size(name) - 1);
    std::memcpy(record.Name, name, sizeof(name));
    return record;
}

OAC_SNAPSHOT_REQUEST ValidSnapshotRequest(ULONG operation)
{
    OAC_SNAPSHOT_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_MESSAGE_MANAGE_SNAPSHOT);
    request.Operation = operation;
    request.SnapshotType = OAC_SNAPSHOT_TYPE_KERNEL_MODULES;
    if (operation == OAC_SNAPSHOT_OPERATION_OPEN)
    {
        request.MaximumRecords = 2;
    }
    else
    {
        request.SnapshotId = ValidSnapshotId();
        request.CursorGeneration = 9;
        if (operation == OAC_SNAPSHOT_OPERATION_READ)
            request.MaximumRecords = 2;
    }
    return request;
}

constexpr std::size_t kEvidenceResponseSize =
    offsetof(OAC_EVIDENCE_READ_RESPONSE, Records) +
    2 * sizeof(OAC_V5_EVENT_RECORD);
using EvidenceResponseStorage = std::array<std::byte, kEvidenceResponseSize>;

OAC_EVIDENCE_READ_RESPONSE* ValidEvidenceResponse(
    EvidenceResponseStorage& storage,
    ULONG channel)
{
    storage.fill(std::byte{});
    auto* response = reinterpret_cast<OAC_EVIDENCE_READ_RESPONSE*>(
        storage.data());
    FillSessionHeader(
        response->Header,
        static_cast<ULONG>(storage.size()),
        OAC_MESSAGE_READ_EVIDENCE);
    response->Channel = channel;
    response->RecordCount = 2;
    response->PublishedSequence = 12;
    response->FirstAvailableSequence = 11;
    response->LastAvailableSequence = 12;
    response->Records[0] = ValidEventRecord();
    response->Records[1] = ValidEventRecord();
    response->Records[1].Sequence = 12;
    if (channel == OAC_EVIDENCE_CHANNEL_ALERT)
    {
        response->Records[0].ObservationSeverity =
            OAC_V5_OBSERVATION_HIGH;
        response->Records[1].ObservationSeverity =
            OAC_V5_OBSERVATION_HIGH;
    }
    return response;
}

constexpr std::size_t kSnapshotResponseSize =
    offsetof(OAC_SNAPSHOT_RESPONSE, Records) +
    2 * sizeof(OAC_SNAPSHOT_RECORD);
using SnapshotResponseStorage = std::array<std::byte, kSnapshotResponseSize>;

OAC_SNAPSHOT_RESPONSE* ValidSnapshotResponse(
    SnapshotResponseStorage& storage)
{
    storage.fill(std::byte{});
    auto* response = reinterpret_cast<OAC_SNAPSHOT_RESPONSE*>(
        storage.data());
    FillSessionHeader(
        response->Header,
        static_cast<ULONG>(storage.size()),
        OAC_MESSAGE_MANAGE_SNAPSHOT);
    response->SnapshotId = ValidSnapshotId();
    response->ScanId = 5;
    response->CreatedTimestamp100ns = 100;
    response->ExpirationInterruptTime100ns = 200;
    response->CursorGeneration = 9;
    response->NextCursor = 2;
    response->SnapshotType = OAC_SNAPSHOT_TYPE_KERNEL_MODULES;
    response->State = OAC_SNAPSHOT_STATE_READY;
    response->TotalItems = 2;
    response->AvailableItems = 2;
    response->RecordCount = 2;
    response->Records[0] = ValidSnapshotRecord(0);
    response->Records[1] = ValidSnapshotRecord(1);
    return response;
}

void TestCodes(TestLog& log)
{
    const std::array<DWORD, 18> codes =
    {
        IOCTL_OAC_PING,
        IOCTL_OAC_CONFIGURE,
        IOCTL_OAC_RUN_KERNEL_SCAN,
        IOCTL_OAC_GET_FINDINGS,
        IOCTL_OAC_CPU_SNAPSHOT,
        IOCTL_OAC_GET_STATUS,
        IOCTL_OAC_V5_NEGOTIATE,
        IOCTL_OAC_V5_CLAIM_SESSION,
        IOCTL_OAC_V5_SET_CONFIG,
        IOCTL_OAC_V5_RUN_SCAN,
        IOCTL_OAC_READ_EVIDENCE,
        IOCTL_OAC_MANAGE_SNAPSHOT,
        IOCTL_OAC_V5_GET_STATUS,
        IOCTL_OAC_V5_REVOKE_SESSION,
        IOCTL_OAC_ARM_LAUNCH,
        IOCTL_OAC_CANCEL_LAUNCH,
        IOCTL_OAC_CONFIRM_TARGET,
        IOCTL_OAC_TEST_INJECT_EVIDENCE
    };
    const std::set<DWORD> unique(codes.begin(), codes.end());
    const std::array<OAC_V5_MESSAGE_TYPE, 11> messages =
    {
        OAC_V5_MESSAGE_NEGOTIATE,
        OAC_V5_MESSAGE_CLAIM_SESSION,
        OAC_V5_MESSAGE_SET_CONFIG,
        OAC_V5_MESSAGE_RUN_SCAN,
        OAC_MESSAGE_READ_EVIDENCE,
        OAC_MESSAGE_MANAGE_SNAPSHOT,
        OAC_V5_MESSAGE_GET_STATUS,
        OAC_V5_MESSAGE_REVOKE_SESSION,
        OAC_MESSAGE_ARM_LAUNCH,
        OAC_MESSAGE_CANCEL_LAUNCH,
        OAC_MESSAGE_CONFIRM_TARGET
    };
    bool buffered = true;
    bool restricted = true;
    bool messageMatch = true;
    for (std::size_t index = 6;
         index < 6 + messages.size();
         ++index)
    {
        buffered = buffered && METHOD_FROM_CTL_CODE(codes[index]) == METHOD_BUFFERED;
        restricted = restricted &&
            ((codes[index] >> 14) & 3UL) == OAC_V5_IOCTL_ACCESS;
        messageMatch = messageMatch &&
            ((codes[index] >> 2) & 0xFFFUL) == messages[index - 6];
    }
    buffered = buffered &&
        METHOD_FROM_CTL_CODE(IOCTL_OAC_TEST_INJECT_EVIDENCE) == METHOD_BUFFERED;
    restricted = restricted &&
        ((IOCTL_OAC_TEST_INJECT_EVIDENCE >> 14) & 3UL) ==
            OAC_V5_IOCTL_ACCESS;
    log.Expect("diagnostic and production IOCTLs are distinct",
        unique.size() == codes.size());
    log.Expect("production and test IOCTLs use buffered I/O", buffered);
    log.Expect("production and test IOCTLs require read and write access",
        restricted);
    log.Expect("production message IDs match IOCTL functions", messageMatch);
    log.Expect("first v5 message type is valid", OacV5MessageTypeValid(
        OAC_V5_MESSAGE_NEGOTIATE) != FALSE);
    log.Expect("last v5 message type is valid", OacV5MessageTypeValid(
        OAC_MESSAGE_CONFIRM_TARGET) != FALSE);
    log.Expect("message below range is invalid", OacV5MessageTypeValid(
        OAC_V5_MESSAGE_NEGOTIATE - 1) == FALSE);
    log.Expect("message above range is invalid", OacV5MessageTypeValid(
        OAC_MESSAGE_CONFIRM_TARGET + 1) == FALSE);
}

void TestBasicHelpers(TestLog& log)
{
    const OAC_V5_SESSION_ID zero{};
    const OAC_V5_SESSION_ID first{1, 2};
    const OAC_V5_SESSION_ID same{1, 2};
    const OAC_V5_SESSION_ID other{1, 3};
    const OAC_LAUNCH_ID zeroLaunch{};
    const OAC_LAUNCH_ID launch{3, 4};
    const OAC_LAUNCH_ID sameLaunch{3, 4};
    const OAC_LAUNCH_ID otherLaunch{3, 5};
    std::array<UCHAR, 8> reserved{};

    log.Expect("C translation unit accepts v5", OacV5CProbe() != 0);
    log.Expect("zero session ID", OacV5SessionIdIsZero(&zero) != FALSE);
    log.Expect("nonzero session ID", OacV5SessionIdIsZero(&first) == FALSE);
    log.Expect("equal session IDs", OacV5SessionIdEqual(&first, &same) != FALSE);
    log.Expect("different session IDs", OacV5SessionIdEqual(&first, &other) == FALSE);
    log.Expect("null session ID is not zero", OacV5SessionIdIsZero(nullptr) == FALSE);
    log.Expect("production protocol exact revision",
        OAC_PRODUCTION_PROTOCOL_VERSION == 0x00050006UL);
    log.Expect("launcher-service protocol exact revision",
        OAC_IPC_PROTOCOL_REVISION == 0x00010006u);
    log.Expect("compatibility alias selects production revision",
        OAC_V5_VERSION == OAC_PRODUCTION_PROTOCOL_VERSION);
    log.Expect("legacy production revision is rejected", OacV5ValidateVersion(
        0x00050000UL) == OAC_V5_INVALID_VERSION);
    log.Expect("zero launch ID", OacLaunchIdIsZero(&zeroLaunch) != FALSE);
    log.Expect("nonzero launch ID", OacLaunchIdIsZero(&launch) == FALSE);
    log.Expect("equal launch IDs", OacLaunchIdEqual(
        &launch, &sameLaunch) != FALSE);
    log.Expect("different launch IDs", OacLaunchIdEqual(
        &launch, &otherLaunch) == FALSE);
    log.Expect("null launch ID is not zero", OacLaunchIdIsZero(
        nullptr) == FALSE);
    log.Expect("valid launch ID", OacValidateLaunchId(
        &launch) == OAC_V5_VALID);
    log.Expect("zero launch ID is invalid", OacValidateLaunchId(
        &zeroLaunch) == OAC_V5_INVALID_VALUE);
    const OAC_SNAPSHOT_ID zeroSnapshot{};
    const OAC_SNAPSHOT_ID snapshot{5, 6};
    const OAC_SNAPSHOT_ID sameSnapshot{5, 6};
    const OAC_SNAPSHOT_ID otherSnapshot{5, 7};
    log.Expect("zero snapshot ID", OacSnapshotIdIsZero(
        &zeroSnapshot) != FALSE);
    log.Expect("nonzero snapshot ID", OacSnapshotIdIsZero(
        &snapshot) == FALSE);
    log.Expect("equal snapshot IDs", OacSnapshotIdEqual(
        &snapshot, &sameSnapshot) != FALSE);
    log.Expect("different snapshot IDs", OacSnapshotIdEqual(
        &snapshot, &otherSnapshot) == FALSE);
    log.Expect("null snapshot ID is not zero", OacSnapshotIdIsZero(
        nullptr) == FALSE);
    log.Expect("alert evidence channel", OacEvidenceChannelValid(
        OAC_EVIDENCE_CHANNEL_ALERT) != FALSE);
    log.Expect("event evidence channel", OacEvidenceChannelValid(
        OAC_EVIDENCE_CHANNEL_EVENT) != FALSE);
    log.Expect("unknown evidence channel", OacEvidenceChannelValid(0) == FALSE);
    log.Expect("snapshot open operation", OacSnapshotOperationValid(
        OAC_SNAPSHOT_OPERATION_OPEN) != FALSE);
    log.Expect("unknown snapshot operation", OacSnapshotOperationValid(0) == FALSE);
    log.Expect("valid exact size", OacV5ValidateSize(64, 64, 32, 64) == OAC_V5_VALID);
    log.Expect("stated size mismatch", OacV5ValidateSize(64, 63, 32, 64) == OAC_V5_INVALID_LENGTH);
    log.Expect("invalid size bounds", OacV5ValidateSize(64, 64, 65, 64) == OAC_V5_INVALID_LENGTH);
    log.Expect("known flags", OacV5ValidateFlags(3, 7) == OAC_V5_VALID);
    log.Expect("unknown flags", OacV5ValidateFlags(8, 7) == OAC_V5_INVALID_FLAGS);
    log.Expect("zero reserved bytes", OacV5ValidateReserved(reserved.data(),
        static_cast<ULONG>(reserved.size())) == OAC_V5_VALID);
    reserved[7] = 1;
    log.Expect("nonzero reserved byte", OacV5ValidateReserved(reserved.data(),
        static_cast<ULONG>(reserved.size())) == OAC_V5_INVALID_RESERVED);
    log.Expect("empty reserved field", OacV5ValidateReserved(nullptr, 0) == OAC_V5_VALID);
    log.Expect("null reserved buffer", OacV5ValidateReserved(nullptr, 1) == OAC_V5_INVALID_POINTER);
}

void TestServiceFailures(TestLog& log)
{
    constexpr uint32_t encoded = OAC_SERVICE_FAILURE_MAGIC |
        (OAC_SERVICE_STAGE_DRIVER_OPEN <<
            OAC_SERVICE_FAILURE_STAGE_SHIFT) |
        ERROR_ACCESS_DENIED;
    log.Expect("service failure encoding", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_DRIVER_OPEN, ERROR_ACCESS_DENIED) == encoded);
    log.Expect("service policy denial retains startup stage",
        OacEncodeServiceFailure(
            OAC_SERVICE_STAGE_BOOTSTRAP,
            ERROR_ACCESS_DISABLED_BY_POLICY) != 0);

    uint32_t stage = 0;
    uint32_t error = 0;
    log.Expect("service failure decoding", OacDecodeServiceFailure(
        encoded, &stage, &error) != 0 &&
        stage == OAC_SERVICE_STAGE_DRIVER_OPEN &&
        error == ERROR_ACCESS_DENIED);
    log.Expect("service failure zero stage", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_NONE, ERROR_ACCESS_DENIED) == 0);
    log.Expect("service failure unknown stage", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_BACKEND + 1, ERROR_ACCESS_DENIED) == 0);
    log.Expect("service failure zero error", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_IDENTITY, ERROR_SUCCESS) == 0);
    log.Expect("service failure oversized error", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_IDENTITY,
        OAC_SERVICE_FAILURE_ERROR_MASK + 1) == 0);
    log.Expect("service failure bad signature", OacDecodeServiceFailure(
        encoded ^ 0x01000000u, &stage, &error) == 0);
    log.Expect("service failure null output", OacDecodeServiceFailure(
        encoded, nullptr, &error) == 0 && OacDecodeServiceFailure(
        encoded, &stage, nullptr) == 0);

    bool roundTrips = true;
    constexpr std::array<uint32_t, 3> errors{
        1,
        ERROR_ACCESS_DENIED,
        OAC_SERVICE_FAILURE_ERROR_MASK
    };
    for (uint32_t expectedStage = OAC_SERVICE_STAGE_BOOTSTRAP;
         expectedStage <= OAC_SERVICE_STAGE_BACKEND;
         ++expectedStage)
    {
        for (const uint32_t expectedError : errors)
        {
            stage = 0;
            error = 0;
            const uint32_t value = OacEncodeServiceFailure(
                expectedStage, expectedError);
            roundTrips = roundTrips && value != 0 &&
                OacDecodeServiceFailure(value, &stage, &error) != 0 &&
                stage == expectedStage && error == expectedError;
        }
    }
    log.Expect("service failure round trips", roundTrips);

    constexpr uint32_t sentinelStage = 0x11223344u;
    constexpr uint32_t sentinelError = 0x55667788u;
    constexpr std::array<uint32_t, 5> invalid{
        0,
        OAC_SERVICE_FAILURE_MAGIC | ERROR_ACCESS_DENIED,
        OAC_SERVICE_FAILURE_MAGIC |
            (OAC_SERVICE_STAGE_DRIVER_OPEN <<
                OAC_SERVICE_FAILURE_STAGE_SHIFT),
        OAC_SERVICE_FAILURE_MAGIC |
            ((OAC_SERVICE_STAGE_BACKEND + 1u) <<
                OAC_SERVICE_FAILURE_STAGE_SHIFT) |
            ERROR_ACCESS_DENIED,
        OAC_SERVICE_FAILURE_MAGIC |
            (15u << OAC_SERVICE_FAILURE_STAGE_SHIFT) |
            ERROR_ACCESS_DENIED
    };
    bool rejectsInvalid = true;
    for (const uint32_t value : invalid)
    {
        stage = sentinelStage;
        error = sentinelError;
        rejectsInvalid = rejectsInvalid &&
            OacDecodeServiceFailure(value, &stage, &error) == 0 &&
            stage == sentinelStage && error == sentinelError;
    }
    log.Expect("service failure rejects malformed values", rejectsInvalid);
    stage = sentinelStage;
    log.Expect("service failure rejects aliased outputs",
        OacDecodeServiceFailure(encoded, &stage, &stage) == 0 &&
        stage == sentinelStage);
}

OAC_IPC_LAUNCH_REQUEST ValidServiceLaunchRequest()
{
    OAC_IPC_LAUNCH_REQUEST request{};
    request.Header.Version = OAC_IPC_PROTOCOL_REVISION;
    request.Header.Size = sizeof(request);
    request.Header.Type = OAC_IPC_TYPE_LAUNCH_REQUEST;
    request.Header.RequestId = 0x123456789ABCDEF0ULL;
    constexpr char16_t path[] = u"C:\\Games\\OAC Game.exe";
    request.ExecutablePathLength =
        static_cast<uint32_t>(std::size(path) - 1);
    for (size_t index = 0; index < std::size(path) - 1; ++index)
        request.ExecutablePath[index] = path[index];
    return request;
}

void SetServiceLaunchPath(
    OAC_IPC_LAUNCH_REQUEST& request,
    const std::u16string& path)
{
    request.ExecutablePathLength = static_cast<uint32_t>(path.size());
    std::fill(
        std::begin(request.ExecutablePath),
        std::end(request.ExecutablePath),
        uint16_t{});
    const size_t count = (std::min)(
        path.size(),
        static_cast<size_t>(OAC_IPC_MAX_EXECUTABLE_PATH_CHARS));
    for (size_t index = 0; index < count; ++index)
        request.ExecutablePath[index] = path[index];
}

void TestServiceLaunchMessages(TestLog& log)
{
    auto request = ValidServiceLaunchRequest();
    log.Expect("service launch request", OacIpcValidateLaunchRequest(
        &request, sizeof(request)) != 0);

    auto invalid = request;
    --invalid.Header.Version;
    log.Expect("service launch revision", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    invalid = request;
    --invalid.Header.Size;
    log.Expect("service launch stated size", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    invalid = request;
    invalid.Header.Type = OAC_IPC_TYPE_STATUS_REQUEST;
    log.Expect("service launch message type", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    invalid = request;
    invalid.Header.RequestId = 0;
    log.Expect("service launch request identity", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    invalid = request;
    invalid.Reserved = 1;
    log.Expect("service launch reserved field", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    log.Expect("service launch exact transport size", OacIpcValidateLaunchRequest(
        &request, sizeof(request) - 1) == 0);

    constexpr std::array invalidPaths{
        u"Games\\Game.exe",
        u"\\\\server\\share\\Game.exe",
        u"C:/Games/Game.exe",
        u"C:\\Games\\..\\Game.exe",
        u"C:\\Games\\.\\Game.exe",
        u"C:\\Games\\\\Game.exe",
        u"C:\\Games\\Game.exe\\",
        u"C:\\Games\\Game.exe.",
        u"C:\\Games\\Game.exe ",
        u"C:\\Games\\Bad:Name.exe",
        u"C:\\Games\\Bad*Name.exe"
    };
    bool rejectsPaths = true;
    for (const auto* path : invalidPaths)
    {
        invalid = request;
        SetServiceLaunchPath(invalid, path);
        rejectsPaths = rejectsPaths &&
            OacIpcValidateLaunchRequest(&invalid, sizeof(invalid)) == 0;
    }
    log.Expect("service launch rejects unsafe paths", rejectsPaths);

    invalid = request;
    invalid.ExecutablePath[4] = 0;
    log.Expect("service launch embedded null", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    invalid = request;
    invalid.ExecutablePath[OAC_IPC_MAX_EXECUTABLE_PATH_CHARS - 1] = u'X';
    log.Expect("service launch dirty path tail", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);
    invalid = request;
    SetServiceLaunchPath(invalid, u"C:\\Games\\\U0001F600.exe");
    log.Expect("service launch valid Unicode path", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) != 0);
    invalid.ExecutablePath[9] = 0xD83D;
    invalid.ExecutablePath[10] = u'X';
    log.Expect("service launch unpaired surrogate", OacIpcValidateLaunchRequest(
        &invalid, sizeof(invalid)) == 0);

    OAC_IPC_LAUNCH_RESPONSE response{};
    response.Header.Version = OAC_IPC_PROTOCOL_REVISION;
    response.Header.Size = sizeof(response);
    response.Header.Type = OAC_IPC_TYPE_LAUNCH_RESPONSE;
    response.Header.RequestId = request.Header.RequestId;
    response.LaunchFlags =
        OAC_IPC_LAUNCH_CONFIRMED | OAC_IPC_LAUNCH_JOB_ASSIGNED |
        OAC_IPC_LAUNCH_RESUMED;
    response.ServiceProcessId = 10;
    response.ClientProcessId = 11;
    response.ClientSessionId = 1;
    response.TargetProcessId = 12;
    log.Expect("service launch success response", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) != 0);

    auto badResponse = response;
    badResponse.LaunchFlags = OAC_IPC_LAUNCH_CONFIRMED |
        OAC_IPC_LAUNCH_RESUMED;
    log.Expect("service launch incomplete response", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    badResponse = response;
    badResponse.TargetProcessId = 0;
    log.Expect("service launch missing target", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    badResponse = response;
    badResponse.FailureStage = OAC_IPC_LAUNCH_STAGE_CONFIRM_TARGET;
    log.Expect("service launch success has no failure stage", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    badResponse = response;
    badResponse.FailureDetail = OAC_IPC_LAUNCH_DETAIL_PATH_MISMATCH;
    log.Expect("service launch success has no failure detail", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    log.Expect("service launch response correlation", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId + 1) == 0);

    response = {};
    response.Header.Version = OAC_IPC_PROTOCOL_REVISION;
    response.Header.Size = sizeof(response);
    response.Header.Type = OAC_IPC_TYPE_LAUNCH_RESPONSE;
    response.Header.RequestId = request.Header.RequestId;
    response.Win32Error = ERROR_ACCESS_DENIED;
    response.FailureStage = OAC_IPC_LAUNCH_STAGE_CREATE_PROCESS;
    response.FailureDetail = OAC_IPC_LAUNCH_DETAIL_PATH_MISMATCH;
    log.Expect("service launch rejection response", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) != 0);
    response.FailureStage = OAC_IPC_LAUNCH_STAGE_VERIFY_MANIFEST;
    response.FailureDetail = OAC_IPC_LAUNCH_DETAIL_MANIFEST_EXPIRED;
    log.Expect("service launch manifest rejection response",
        OacIpcValidateLaunchResponse(
            &response, sizeof(response), request.Header.RequestId) != 0);
    response.TargetProcessId = 12;
    log.Expect("service launch rejection has no identity", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) == 0);
    response.TargetProcessId = 0;
    response.FailureStage = OAC_IPC_LAUNCH_STAGE_NONE;
    log.Expect("service launch rejection names its stage", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) == 0);
    response.FailureStage = OAC_IPC_LAUNCH_STAGE_VERIFY_MANIFEST + 1;
    log.Expect("service launch rejection stage range", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) == 0);
    response.FailureStage = OAC_IPC_LAUNCH_STAGE_CREATE_PROCESS;
    response.FailureDetail = OAC_IPC_LAUNCH_DETAIL_BACKEND + 1;
    log.Expect("service launch rejection detail range", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) == 0);
}

void TestServiceScanMetrics(TestLog& log)
{
    OAC_IPC_SCAN_METRICS metrics{};
    log.Expect("zero scanner metrics", OacIpcScanMetricsAreZero(&metrics) != 0);
    log.Expect("unavailable scanner metrics", OacIpcScanMetricsValid(&metrics) != 0);

    metrics.HealthIterations = 2;
    metrics.MaximumHealthDelay100ns = 250 *
        oac::kHundredNanosecondsPerMillisecond;
    log.Expect("health metrics before target", OacIpcScanMetricsValid(&metrics) != 0);
    log.Expect("health metrics are not empty", OacIpcScanMetricsAreZero(&metrics) == 0);

    metrics.State = OAC_IPC_SCAN_READY;
    metrics.SlicesQueued = 1;
    metrics.SlicesCompleted = 1;
    metrics.MemoryRegionsInspected = 8;
    metrics.ThreadsInspected = 1;
    metrics.MaximumSliceDuration100ns = 15000;
    metrics.MaximumThreadSuspension100ns = 1000;
    metrics.LastStartTime100ns = 100;
    metrics.LastEndTime100ns = 200;
    metrics.LastCpuTime100ns = 50;
    metrics.LastItemsInspected = 9;
    metrics.PeakWorkingBufferBytes = oac::kMemorySampleBytes;
    metrics.LastOutcome = OAC_IPC_SCAN_OUTCOME_PARTIAL;
    log.Expect("valid partial scanner metrics", OacIpcScanMetricsValid(&metrics) != 0);

    auto invalid = metrics;
    invalid.SlicesCompleted = 2;
    log.Expect("scanner completion cannot exceed queue", OacIpcScanMetricsValid(&invalid) == 0);
    invalid = metrics;
    invalid.SlicesCancelled = 1;
    log.Expect("scanner terminal counts cannot overlap", OacIpcScanMetricsValid(&invalid) == 0);
    invalid = metrics;
    invalid.SweepsCompleted = 2;
    log.Expect("scanner sweep requires completed slice", OacIpcScanMetricsValid(&invalid) == 0);
    invalid = metrics;
    invalid.LastEndTime100ns = 99;
    log.Expect("scanner timestamps are ordered", OacIpcScanMetricsValid(&invalid) == 0);
    invalid = metrics;
    invalid.LastError = ERROR_TIMEOUT;
    log.Expect("successful scanner result has no error", OacIpcScanMetricsValid(&invalid) == 0);
    invalid = metrics;
    invalid.State = OAC_IPC_SCAN_FAILED;
    log.Expect("failed scanner state names failure", OacIpcScanMetricsValid(&invalid) == 0);
    invalid.LastOutcome = OAC_IPC_SCAN_OUTCOME_FAILED;
    invalid.LastError = ERROR_TIMEOUT;
    log.Expect("valid failed scanner metrics", OacIpcScanMetricsValid(&invalid) != 0);
    invalid = metrics;
    invalid.State = OAC_IPC_SCAN_UNAVAILABLE;
    log.Expect("unavailable scanner has no work", OacIpcScanMetricsValid(&invalid) == 0);
    invalid = metrics;
    invalid.Reserved = 1;
    log.Expect("scanner metrics reserved field", OacIpcScanMetricsValid(&invalid) == 0);

    oac::ScanSliceBudget budget{};
    budget.deadline100ns = 1000;
    budget.byteLimit = 64;
    budget.regionLimit = 2;
    budget.threadLimit = 1;
    oac::ScanSliceProgress progress{};
    log.Expect("scan budget initially permits work",
        oac::CanInspectMemory(budget, progress, 999) &&
        oac::CanInspectThread(budget, progress, 999));
    progress.bytesRead = budget.byteLimit;
    log.Expect("scan byte budget is bounded",
        !oac::CanInspectMemory(budget, progress, 999));
    progress = {};
    progress.regionAttempts = budget.regionLimit;
    log.Expect("scan region budget is bounded",
        !oac::CanInspectMemory(budget, progress, 999));
    progress = {};
    progress.threadsInspected = budget.threadLimit;
    log.Expect("scan thread budget is bounded",
        !oac::CanInspectThread(budget, progress, 999));
    progress = {};
    log.Expect("scan deadline is bounded",
        !oac::CanInspectMemory(budget, progress, budget.deadline100ns) &&
        !oac::CanInspectThread(budget, progress, budget.deadline100ns));
}

void TestServiceBackendStatus(TestLog& log)
{
    OAC_IPC_BACKEND_STATUS status{};
    log.Expect("zero backend status", OacIpcBackendStatusAreZero(
        &status) != 0);
    log.Expect("empty backend status is not active",
        OacIpcBackendStatusValid(&status) == 0);

    status.LeaseState = OAC_LEASE_HEALTHY;
    status.Flags = OAC_IPC_BACKEND_AUTHENTICATED |
        OAC_IPC_BACKEND_TEST_DOUBLE;
    status.LeaseSequence = 1;
    log.Expect("healthy backend status", OacIpcBackendStatusValid(
        &status) != 0);
    status.LeaseState = OAC_LEASE_DEGRADED;
    log.Expect("degraded backend status", OacIpcBackendStatusValid(
        &status) != 0);
    status.LeaseState = OAC_LEASE_EXPIRED;
    status.LastError = ERROR_TIMEOUT;
    log.Expect("expired backend status names its failure",
        OacIpcBackendStatusValid(&status) != 0);
    status.LastError = ERROR_SUCCESS;
    log.Expect("expired backend status requires an error",
        OacIpcBackendStatusValid(&status) == 0);
    status.LeaseState = OAC_LEASE_HEALTHY;
    status.LastError = ERROR_INVALID_DATA;
    log.Expect("healthy backend status rejects an error",
        OacIpcBackendStatusValid(&status) == 0);
    status.LastError = ERROR_SUCCESS;
    status.Flags = OAC_IPC_BACKEND_TEST_DOUBLE;
    log.Expect("backend status requires authentication",
        OacIpcBackendStatusValid(&status) == 0);
    status.Flags = OAC_IPC_BACKEND_AUTHENTICATED | 0x80000000u;
    log.Expect("backend status rejects unknown flags",
        OacIpcBackendStatusValid(&status) == 0);
}

struct SuspensionTargetContext
{
    HANDLE readyEvent = nullptr;
    HANDLE releaseEvent = nullptr;
};

DWORD WINAPI SuspensionTarget(void* rawContext)
{
    const auto* context = static_cast<const SuspensionTargetContext*>(rawContext);
    if (!SetEvent(context->readyEvent)) return 1;
    return WaitForSingleObject(context->releaseEvent, 5000) == WAIT_OBJECT_0
        ? 0
        : 2;
}

void TestThreadSuspension(TestLog& log)
{
    const auto runCase = [&log](bool explicitResume, const char* name)
    {
        SuspensionTargetContext context{};
        context.readyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        context.releaseEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE thread = nullptr;
        bool passed = context.readyEvent != nullptr && context.releaseEvent != nullptr;
        if (passed)
        {
            thread = CreateThread(nullptr, 0, SuspensionTarget, &context, 0, nullptr);
            passed = thread != nullptr &&
                WaitForSingleObject(context.readyEvent, 5000) == WAIT_OBJECT_0;
        }
        if (passed)
        {
            {
                oac::ScopedThreadSuspension suspension(thread);
                passed = suspension.Active();
                if (passed && explicitResume)
                    passed = suspension.Resume() == ERROR_SUCCESS;
            }
            (void)SetEvent(context.releaseEvent);
            passed = passed &&
                WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0;
        }
        if (thread != nullptr)
        {
            (void)SetEvent(context.releaseEvent);
            (void)WaitForSingleObject(thread, 5000);
            CloseHandle(thread);
        }
        if (context.releaseEvent != nullptr) CloseHandle(context.releaseEvent);
        if (context.readyEvent != nullptr) CloseHandle(context.readyEvent);
        log.Expect(name, passed);
    };

    runCase(true, "sampled thread resumes explicitly");
    runCase(false, "sampled thread resumes during scope cleanup");
    oac::ScopedThreadSuspension invalid(nullptr);
    log.Expect("invalid thread cannot be suspended",
        !invalid.Active() && invalid.Error() == ERROR_INVALID_HANDLE);
}

void TestRanges(TestLog& log)
{
    log.Expect("valid array range", OacV5ValidateRange(96, 32, 8, 8, 32, 8) == OAC_V5_VALID);
    log.Expect("valid empty range", OacV5ValidateRange(32, 32, 0, 8, 32, 8) == OAC_V5_VALID);
    log.Expect("range before payload", OacV5ValidateRange(96, 24, 1, 8, 32, 8) == OAC_V5_INVALID_RANGE);
    log.Expect("range offset outside", OacV5ValidateRange(96, 104, 0, 8, 32, 8) == OAC_V5_INVALID_RANGE);
    log.Expect("range end outside", OacV5ValidateRange(96, 88, 2, 8, 32, 8) == OAC_V5_INVALID_RANGE);
    log.Expect("range product overflow", OacV5ValidateRange(OAC_V5_ULONG_MAX, 32,
        OAC_V5_ULONG_MAX, 8,
        32, 8) == OAC_V5_INVALID_RANGE);
    log.Expect("range misalignment", OacV5ValidateRange(96, 36, 1, 8, 32, 8) == OAC_V5_INVALID_ALIGNMENT);
    log.Expect("range bad alignment", OacV5ValidateRange(96, 32, 1, 8, 32, 3) == OAC_V5_INVALID_VALUE);
    log.Expect("range zero element", OacV5ValidateRange(96, 32, 1, 0, 32, 8) == OAC_V5_INVALID_VALUE);
}

void TestNegotiateRequest(TestLog& log)
{
    auto request = ValidNegotiateRequest();
    log.Expect("valid negotiate request", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    log.Expect("null negotiate request", OacV5ValidateNegotiateRequest(
        nullptr, sizeof(request)) == OAC_V5_INVALID_POINTER);
    log.Expect("truncated negotiate request", OacV5ValidateNegotiateRequest(
        &request, sizeof(request) - 1) == OAC_V5_INVALID_LENGTH);
    log.Expect("oversized negotiate request", OacV5ValidateNegotiateRequest(
        &request, sizeof(request) + 1) == OAC_V5_INVALID_LENGTH);

    request = ValidNegotiateRequest();
    --request.Header.Size;
    log.Expect("negotiate stated size", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_LENGTH);
    request = ValidNegotiateRequest();
    request.Header.Version = OAC_PROTOCOL_VERSION;
    log.Expect("negotiate v4 header", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VERSION);
    request = ValidNegotiateRequest();
    request.Header.RequestId = 0;
    log.Expect("negotiate zero request ID", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_REQUEST_ID);
    request = ValidNegotiateRequest();
    request.Header.Flags = 1;
    log.Expect("negotiate unknown flags", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_FLAGS);
    request = ValidNegotiateRequest();
    request.Header.MessageType = OAC_V5_MESSAGE_CLAIM_SESSION;
    log.Expect("negotiate wrong message type", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_MESSAGE_TYPE);
    request = ValidNegotiateRequest();
    request.Header.SessionId.Low = 1;
    log.Expect("negotiate carries session", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_SESSION);
    request = ValidNegotiateRequest();
    request.Header.Generation = 1;
    log.Expect("negotiate carries generation", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_GENERATION);
    request = ValidNegotiateRequest();
    request.MinimumVersion = OAC_V5_VERSION + 1;
    request.MaximumVersion = OAC_V5_VERSION;
    log.Expect("negotiate reversed range", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VERSION);
    request = ValidNegotiateRequest();
    request.MinimumVersion = OAC_V5_VERSION - 1;
    request.MaximumVersion = OAC_V5_VERSION - 1;
    log.Expect("negotiate unsupported older range", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VERSION);
    request = ValidNegotiateRequest();
    request.MinimumVersion = OAC_V5_VERSION + 1;
    request.MaximumVersion = OAC_V5_VERSION + 1;
    log.Expect("negotiate unsupported newer range", OacV5ValidateNegotiateRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VERSION);
}

void TestClaimAndStatusRequests(TestLog& log)
{
    auto claim = ValidClaimRequest();
    log.Expect("valid production claim", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_VALID);
    claim.Mode = OAC_V5_SESSION_DIAGNOSTIC;
    std::fill(
        std::begin(claim.BackendBindingSha256),
        std::end(claim.BackendBindingSha256),
        UCHAR{0});
    log.Expect("valid diagnostic claim", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_VALID);
    claim = ValidClaimRequest();
    std::fill(
        std::begin(claim.BackendBindingSha256),
        std::end(claim.BackendBindingSha256),
        UCHAR{0});
    log.Expect("production claim requires backend binding",
        OacV5ValidateClaimRequest(
            &claim, sizeof(claim)) == OAC_V5_INVALID_VALUE);
    claim = ValidClaimRequest();
    claim.Mode = OAC_V5_SESSION_DIAGNOSTIC;
    log.Expect("diagnostic claim rejects backend binding",
        OacV5ValidateClaimRequest(
            &claim, sizeof(claim)) == OAC_V5_INVALID_VALUE);
    claim = ValidClaimRequest();
    claim.Mode = 0;
    log.Expect("claim invalid mode", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_INVALID_VALUE);
    claim = ValidClaimRequest();
    claim.Reserved = 1;
    log.Expect("claim reserved field", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_INVALID_RESERVED);
    claim = ValidClaimRequest();
    claim.Header.SessionId.High = 1;
    log.Expect("claim carries session", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_INVALID_SESSION);
    log.Expect("claim truncated", OacV5ValidateClaimRequest(
        &claim, sizeof(claim) - 1) == OAC_V5_INVALID_LENGTH);
    claim = ValidClaimRequest();
    claim.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    log.Expect("claim wrong message type", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_INVALID_MESSAGE_TYPE);

    auto status = ValidStatusRequest();
    log.Expect("valid status request", OacV5ValidateStatusRequest(
        &status, sizeof(status)) == OAC_V5_VALID);
    status.Header.SessionId = {};
    log.Expect("status zero session", OacV5ValidateStatusRequest(
        &status, sizeof(status)) == OAC_V5_INVALID_SESSION);
    status = ValidStatusRequest();
    status.Header.Generation = 0;
    log.Expect("status zero generation", OacV5ValidateStatusRequest(
        &status, sizeof(status)) == OAC_V5_INVALID_GENERATION);
    status = ValidStatusRequest();
    status.Header.Flags = 1;
    log.Expect("status unknown flags", OacV5ValidateStatusRequest(
        &status, sizeof(status)) == OAC_V5_INVALID_FLAGS);
    status = ValidStatusRequest();
    status.Header.MessageType = OAC_V5_MESSAGE_RUN_SCAN;
    log.Expect("status wrong message type", OacV5ValidateStatusRequest(
        &status, sizeof(status)) == OAC_V5_INVALID_MESSAGE_TYPE);
    log.Expect("status oversized", OacV5ValidateStatusRequest(
        &status, sizeof(status) + 8) == OAC_V5_INVALID_LENGTH);
}

void TestRevokeMessages(TestLog& log)
{
    auto request = ValidRevokeRequest();
    log.Expect("valid explicit revoke request", OacValidateRevokeSessionRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    log.Expect("revoke request exact size", OacValidateRevokeSessionRequest(
        &request, sizeof(request) - 1) == OAC_V5_INVALID_LENGTH);
    request.Header.MessageType = OAC_V5_MESSAGE_GET_STATUS;
    log.Expect("revoke request message type", OacValidateRevokeSessionRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_MESSAGE_TYPE);
    request = ValidRevokeRequest();
    request.RevokeReason = OAC_V5_REVOKE_SERVICE_EXIT;
    log.Expect("revoke request only accepts caller revocation",
        OacValidateRevokeSessionRequest(
            &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidRevokeRequest();
    request.Reserved = 1;
    log.Expect("revoke request reserved field", OacValidateRevokeSessionRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_RESERVED);

    auto response = ValidRevokeResponse();
    log.Expect("valid explicit revoke response", OacValidateRevokeSessionResponse(
        &response, sizeof(response)) == OAC_V5_VALID);
    log.Expect("revoke response exact size", OacValidateRevokeSessionResponse(
        &response, sizeof(response) + 1) == OAC_V5_INVALID_LENGTH);
    response.Header.Flags = 0;
    log.Expect("revoke response requires terminal flag",
        OacValidateRevokeSessionResponse(
            &response, sizeof(response)) == OAC_V5_INVALID_VALUE);
    response = ValidRevokeResponse();
    response.State = OAC_V5_SESSION_MONITORING;
    log.Expect("revoke response requires terminal state",
        OacValidateRevokeSessionResponse(
            &response, sizeof(response)) == OAC_V5_INVALID_VALUE);
    response = ValidRevokeResponse();
    response.RevokeReason = OAC_V5_REVOKE_NONE;
    log.Expect("revoke response requires provenance",
        OacValidateRevokeSessionResponse(
            &response, sizeof(response)) == OAC_V5_INVALID_VALUE);
    response = ValidRevokeResponse();
    response.SessionLossSequence = 0;
    log.Expect("revoke response liveness pair",
        OacValidateRevokeSessionResponse(
            &response, sizeof(response)) == OAC_V5_INVALID_VALUE);
    response = ValidRevokeResponse();
    response.Reserved = 1;
    log.Expect("revoke response reserved field",
        OacValidateRevokeSessionResponse(
            &response, sizeof(response)) == OAC_V5_INVALID_RESERVED);
}

void TestLaunchRequests(TestLog& log)
{
    auto arm = ValidArmLaunchRequest();
    log.Expect("valid arm-launch request", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_VALID);
    log.Expect("null arm-launch request", OacValidateArmLaunchRequest(
        nullptr, sizeof(arm)) == OAC_V5_INVALID_POINTER);
    log.Expect("truncated arm-launch request", OacValidateArmLaunchRequest(
        &arm, sizeof(arm) - 1) == OAC_V5_INVALID_LENGTH);
    log.Expect("oversized arm-launch request", OacValidateArmLaunchRequest(
        &arm, sizeof(arm) + 1) == OAC_V5_INVALID_LENGTH);

    arm = ValidArmLaunchRequest();
    arm.Header.Version = 0x00050000UL;
    log.Expect("arm-launch rejects legacy production revision", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_VERSION);
    arm = ValidArmLaunchRequest();
    arm.Header.MessageType = OAC_MESSAGE_CANCEL_LAUNCH;
    log.Expect("arm-launch wrong message type", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_MESSAGE_TYPE);
    arm = ValidArmLaunchRequest();
    arm.Header.SessionId = {};
    log.Expect("arm-launch requires session", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_SESSION);
    arm = ValidArmLaunchRequest();
    arm.TimeToLiveMilliseconds = OAC_LAUNCH_MIN_TTL_MS - 1;
    log.Expect("arm-launch TTL below bound", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_RANGE);
    arm.TimeToLiveMilliseconds = OAC_LAUNCH_MAX_TTL_MS + 1;
    log.Expect("arm-launch TTL above bound", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_RANGE);
    arm = ValidArmLaunchRequest();
    arm.Reserved = 1;
    log.Expect("arm-launch reserved field", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_RESERVED);
    arm = ValidArmLaunchRequest();
    std::memset(arm.ManifestSha256, 0, sizeof(arm.ManifestSha256));
    log.Expect("arm-launch requires manifest identity",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);

    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\dEvIcE\\HarddiskVolume3\\Games\\OAC.exe");
    log.Expect("canonical path prefix requires canonical case",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\DosDevices\\C\\OAC.exe");
    log.Expect("canonical path requires Device namespace",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPathLength = 8;
    log.Expect("canonical path rejects empty Device namespace",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_RANGE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPathLength = OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS;
    log.Expect("canonical path reserves a terminator",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_RANGE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\Games\\OAC.exe:");
    log.Expect("canonical path rejects colon", OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3/Games/OAC.exe");
    log.Expect("canonical path rejects forward slash",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPath[10] = static_cast<WCHAR>(0x1f);
    log.Expect("canonical path rejects control character",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\\\OAC.exe");
    log.Expect("canonical path rejects repeated separator",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\Games\\");
    log.Expect("canonical path rejects trailing separator",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\.\\OAC.exe");
    log.Expect("canonical path rejects dot component",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\..\\OAC.exe");
    log.Expect("canonical path rejects dot-dot component",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\OAC.\\game.exe");
    log.Expect("canonical path rejects component trailing dot",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalPath(arm, L"\\Device\\HarddiskVolume3\\OAC \\game.exe");
    log.Expect("canonical path rejects component trailing space",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPath[10] = L'\0';
    log.Expect("canonical path rejects embedded null",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPath[8] = static_cast<WCHAR>(0xd83d);
    arm.CanonicalNtPath[9] = static_cast<WCHAR>(0xde00);
    log.Expect("canonical path accepts UTF-16 surrogate pair",
        OacValidateArmLaunchRequest(&arm, sizeof(arm)) == OAC_V5_VALID);
    arm.CanonicalNtPath[9] = L'A';
    log.Expect("canonical path rejects unpaired high surrogate",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPath[8] = static_cast<WCHAR>(0xdc00);
    log.Expect("canonical path rejects unpaired low surrogate",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalNtPath[std::size(kValidLaunchPath) - 1] = L'X';
    log.Expect("canonical path rejects nonzero unused tail",
        OacValidateArmLaunchRequest(
        &arm, sizeof(arm)) == OAC_V5_INVALID_RESERVED);

    arm = ValidArmLaunchRequest();
    SetCanonicalDosDevicePath(arm, L"\\?\\C:\\Games\\OAC.exe");
    log.Expect("DOS-device path requires canonical prefix",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    SetCanonicalDosDevicePath(arm, L"\\??\\C:\\Games\\..\\OAC.exe");
    log.Expect("DOS-device path rejects dot-dot component",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchRequest();
    arm.CanonicalDosDevicePath[
        std::size(kValidLaunchDosDevicePath) - 1] = L'X';
    log.Expect("DOS-device path rejects nonzero unused tail",
        OacValidateArmLaunchRequest(
            &arm, sizeof(arm)) == OAC_V5_INVALID_RESERVED);

    auto cancel = ValidCancelLaunchRequest();
    log.Expect("valid cancel-launch request", OacValidateCancelLaunchRequest(
        &cancel, sizeof(cancel)) == OAC_V5_VALID);
    cancel.LaunchId = {};
    log.Expect("cancel-launch rejects zero launch ID",
        OacValidateCancelLaunchRequest(
            &cancel, sizeof(cancel)) == OAC_V5_INVALID_VALUE);
    cancel = ValidCancelLaunchRequest();
    cancel.Header.MessageType = OAC_MESSAGE_ARM_LAUNCH;
    log.Expect("cancel-launch wrong message type",
        OacValidateCancelLaunchRequest(
            &cancel, sizeof(cancel)) == OAC_V5_INVALID_MESSAGE_TYPE);
    log.Expect("cancel-launch rejects extra bytes",
        OacValidateCancelLaunchRequest(
            &cancel, sizeof(cancel) + 1) == OAC_V5_INVALID_LENGTH);

    auto confirm = ValidConfirmTargetRequest();
    log.Expect("valid confirm-target request",
        OacValidateConfirmTargetRequest(
            &confirm, sizeof(confirm)) == OAC_V5_VALID);
    confirm.LaunchId = {};
    log.Expect("confirm-target rejects zero launch ID",
        OacValidateConfirmTargetRequest(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_VALUE);
    confirm = ValidConfirmTargetRequest();
    confirm.TargetProcessHandle = 0;
    log.Expect("confirm-target rejects zero process handle",
        OacValidateConfirmTargetRequest(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_VALUE);
    confirm = ValidConfirmTargetRequest();
    confirm.Header.MessageType = OAC_MESSAGE_CANCEL_LAUNCH;
    log.Expect("confirm-target wrong message type",
        OacValidateConfirmTargetRequest(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_MESSAGE_TYPE);
    log.Expect("confirm-target rejects truncation",
        OacValidateConfirmTargetRequest(
            &confirm, sizeof(confirm) - 1) == OAC_V5_INVALID_LENGTH);
}

void TestLaunchResponses(TestLog& log)
{
    auto arm = ValidArmLaunchResponse();
    log.Expect("valid arm-launch response", OacValidateArmLaunchResponse(
        &arm, sizeof(arm)) == OAC_V5_VALID);
    arm.LaunchId = {};
    log.Expect("arm-launch response requires launch ID",
        OacValidateArmLaunchResponse(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchResponse();
    arm.ExpirationInterruptTime100ns = 0;
    log.Expect("arm-launch response requires deadline",
        OacValidateArmLaunchResponse(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchResponse();
    arm.State = OAC_V5_SESSION_TARGET_BOUND;
    log.Expect("arm-launch response requires pending state",
        OacValidateArmLaunchResponse(
            &arm, sizeof(arm)) == OAC_V5_INVALID_VALUE);
    arm = ValidArmLaunchResponse();
    arm.Reserved = 1;
    log.Expect("arm-launch response reserved field",
        OacValidateArmLaunchResponse(
            &arm, sizeof(arm)) == OAC_V5_INVALID_RESERVED);
    log.Expect("arm-launch response rejects truncation",
        OacValidateArmLaunchResponse(
            &arm, sizeof(arm) - 1) == OAC_V5_INVALID_LENGTH);

    auto cancel = ValidCancelLaunchResponse();
    log.Expect("valid cancel-launch response",
        OacValidateCancelLaunchResponse(
            &cancel, sizeof(cancel)) == OAC_V5_VALID);
    cancel.Header.Flags = 0;
    log.Expect("cancel-launch response requires revoked flag",
        OacValidateCancelLaunchResponse(
            &cancel, sizeof(cancel)) == OAC_V5_INVALID_VALUE);
    cancel = ValidCancelLaunchResponse();
    cancel.State = OAC_V5_SESSION_CLAIMED;
    log.Expect("cancel-launch response is terminal",
        OacValidateCancelLaunchResponse(
            &cancel, sizeof(cancel)) == OAC_V5_INVALID_VALUE);
    cancel = ValidCancelLaunchResponse();
    cancel.Reserved = 1;
    log.Expect("cancel-launch response reserved field",
        OacValidateCancelLaunchResponse(
            &cancel, sizeof(cancel)) == OAC_V5_INVALID_RESERVED);

    auto confirm = ValidConfirmTargetResponse();
    log.Expect("valid confirm-target response",
        OacValidateConfirmTargetResponse(
            &confirm, sizeof(confirm)) == OAC_V5_VALID);
    confirm.TargetProcessId = 0;
    log.Expect("confirm-target response requires PID",
        OacValidateConfirmTargetResponse(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_VALUE);
    confirm = ValidConfirmTargetResponse();
    confirm.State = OAC_V5_SESSION_TARGET_BOUND;
    log.Expect("confirm-target response requires monitoring state",
        OacValidateConfirmTargetResponse(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_VALUE);
    confirm = ValidConfirmTargetResponse();
    confirm.Reserved = 1;
    log.Expect("confirm-target response reserved field",
        OacValidateConfirmTargetResponse(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_RESERVED);
    confirm = ValidConfirmTargetResponse();
    confirm.Header.MessageType = OAC_MESSAGE_ARM_LAUNCH;
    log.Expect("confirm-target response wrong message type",
        OacValidateConfirmTargetResponse(
            &confirm, sizeof(confirm)) == OAC_V5_INVALID_MESSAGE_TYPE);
}

void TestResponses(TestLog& log)
{
    auto negotiate = ValidNegotiateResponse();
    log.Expect("valid negotiate response", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_VALID);
    negotiate.SelectedVersion = OAC_PROTOCOL_VERSION;
    log.Expect("negotiate selected v4", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.Capabilities = 0x80000000UL;
    log.Expect("negotiate unknown capability", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.ProtocolFlags = 0x80000000UL;
    log.Expect("negotiate unknown protocol flag", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.MaximumInputSize = sizeof(OAC_V5_CLAIM_REQUEST) - 1;
    log.Expect("negotiate input limit too small", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.Capabilities |= OAC_V5_CAP_LAUNCH_TICKET;
    negotiate.MaximumInputSize = sizeof(OAC_ARM_LAUNCH_REQUEST) - 1;
    log.Expect("launch capability requires arm request capacity",
        OacV5ValidateNegotiateResponse(
            &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate.MaximumInputSize = sizeof(OAC_ARM_LAUNCH_REQUEST);
    log.Expect("launch capability accepts exact arm request capacity",
        OacV5ValidateNegotiateResponse(
            &negotiate, sizeof(negotiate)) == OAC_V5_VALID);
    negotiate = ValidNegotiateResponse();
    negotiate.MaximumOutputSize = OAC_V5_MAX_OUTPUT_SIZE + 1;
    log.Expect("negotiate output limit too large", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.MaximumEventCount = 0;
    log.Expect("negotiate zero event limit", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.Header.SessionId.High = 1;
    log.Expect("negotiate response carries session", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_SESSION);
    negotiate = ValidNegotiateResponse();
    negotiate.Header.Reason = OAC_V5_REASON_MALFORMED_REQUEST + 1;
    log.Expect("response unknown reason", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_VALUE);
    negotiate = ValidNegotiateResponse();
    negotiate.Header.MessageType = OAC_V5_MESSAGE_GET_STATUS;
    log.Expect("negotiate response wrong message type",
        OacV5ValidateNegotiateResponse(
            &negotiate, sizeof(negotiate)) == OAC_V5_INVALID_MESSAGE_TYPE);
    log.Expect("negotiate response truncated", OacV5ValidateNegotiateResponse(
        &negotiate, sizeof(negotiate) - 1) == OAC_V5_INVALID_LENGTH);

    auto claim = ValidClaimResponse();
    log.Expect("valid claim response", OacV5ValidateClaimResponse(
        &claim, sizeof(claim)) == OAC_V5_VALID);
    claim.Header.SessionId = {};
    log.Expect("claim response zero session", OacV5ValidateClaimResponse(
        &claim, sizeof(claim)) == OAC_V5_INVALID_SESSION);
    claim = ValidClaimResponse();
    claim.Header.Generation = 0;
    log.Expect("claim response zero generation", OacV5ValidateClaimResponse(
        &claim, sizeof(claim)) == OAC_V5_INVALID_GENERATION);
    claim = ValidClaimResponse();
    claim.State = OAC_V5_SESSION_MONITORING;
    log.Expect("claim response wrong state", OacV5ValidateClaimResponse(
        &claim, sizeof(claim)) == OAC_V5_INVALID_VALUE);
    claim = ValidClaimResponse();
    claim.Capabilities = 0x80000000UL;
    log.Expect("claim response unknown capability", OacV5ValidateClaimResponse(
        &claim, sizeof(claim)) == OAC_V5_INVALID_VALUE);
    claim = ValidClaimResponse();
    claim.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    log.Expect("claim response wrong message type", OacV5ValidateClaimResponse(
        &claim, sizeof(claim)) == OAC_V5_INVALID_MESSAGE_TYPE);

    auto status = ValidStatusResponse();
    log.Expect("valid active status response", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_VALID);
    status.State = OAC_V5_SESSION_REVOKED;
    status.RevokeReason = OAC_V5_REVOKE_SERVICE_EXIT;
    status.Header.Flags = OAC_V5_RESPONSE_REVOKED;
    log.Expect("valid revoked status response", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.Header.Flags = OAC_V5_RESPONSE_REVOKED;
    log.Expect("active status rejects revoked response flag",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_REVOKED;
    status.RevokeReason = OAC_V5_REVOKE_SERVICE_EXIT;
    log.Expect("revoked status requires response flag",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_UNCLAIMED;
    log.Expect("status unclaimed with session", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_REVOKED;
    log.Expect("revoked status without reason", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.RevokeReason = OAC_V5_REVOKE_POLICY;
    log.Expect("active status with revoke reason", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.ConfigurationFlags = 0x80000000UL;
    log.Expect("status unknown config flag", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.EventsDropped = status.EventsWritten + 1;
    log.Expect("status drop count cannot exceed published events",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.Header.Flags = OAC_V5_RESPONSE_PARTIAL;
    log.Expect("status disallowed response flag", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_FLAGS);
    status = ValidStatusResponse();
    status.Header.MessageType = OAC_MESSAGE_READ_EVIDENCE;
    log.Expect("status response wrong message type", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_MESSAGE_TYPE);
    status = ValidStatusResponse();
    status.TargetProcessId = 200;
    log.Expect("claimed status rejects target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.ManifestSha256[0] = 1;
    log.Expect("claimed status rejects manifest identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_LAUNCH_PENDING;
    status.TargetProcessId = 200;
    status.ManifestSha256[0] = 1;
    log.Expect("pending status rejects target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_LAUNCH_PENDING;
    log.Expect("pending status requires manifest identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status.ManifestSha256[0] = 1;
    log.Expect("pending status accepts manifest identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_TARGET_BOUND;
    log.Expect("bound status requires target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status.TargetProcessId = 200;
    status.ManifestSha256[0] = 1;
    log.Expect("bound status accepts target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_MONITORING;
    log.Expect("monitoring status requires target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status.TargetProcessId = 200;
    status.ManifestSha256[0] = 1;
    log.Expect("monitoring status accepts target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_REVOKED;
    status.RevokeReason = OAC_REVOKE_TARGET_CONFIRMATION_FAILED;
    status.Header.Flags = OAC_V5_RESPONSE_REVOKED;
    status.TargetProcessId = 200;
    status.ManifestSha256[0] = 1;
    log.Expect("terminal tombstone may retain target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.SessionLossSequence = 1;
    status.LastSessionLossReason = OAC_V5_REVOKE_SERVICE_EXIT;
    log.Expect("status accepts prior session loss",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status.LastSessionLossReason = OAC_V5_REVOKE_NONE;
    log.Expect("status rejects sequence without loss reason",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.LastSessionLossReason = OAC_V5_REVOKE_SERVICE_EXIT;
    log.Expect("status rejects loss reason without sequence",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.SessionMode = 0;
    log.Expect("status rejects invalid session mode",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    std::fill(
        std::begin(status.BackendBindingSha256),
        std::end(status.BackendBindingSha256),
        UCHAR{0});
    log.Expect("production status requires backend binding",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.SessionMode = OAC_V5_SESSION_DIAGNOSTIC;
    std::fill(
        std::begin(status.BackendBindingSha256),
        std::end(status.BackendBindingSha256),
        UCHAR{0});
    log.Expect("diagnostic status omits backend binding",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
}

void TestCorrelationAndIds(TestLog& log)
{
    auto request = ValidStatusRequest();
    auto response = ValidStatusResponse();
    log.Expect("valid response correlation", OacV5ValidateCorrelation(
        &request.Header, &response.Header) == OAC_V5_VALID);
    ++response.Header.RequestId;
    log.Expect("request ID mismatch", OacV5ValidateCorrelation(
        &request.Header, &response.Header) == OAC_V5_INVALID_CORRELATION);
    response = ValidStatusResponse();
    ++response.Header.SessionId.Low;
    log.Expect("session ID mismatch", OacV5ValidateCorrelation(
        &request.Header, &response.Header) == OAC_V5_INVALID_CORRELATION);
    response = ValidStatusResponse();
    ++response.Header.Generation;
    log.Expect("generation mismatch", OacV5ValidateCorrelation(
        &request.Header, &response.Header) == OAC_V5_INVALID_CORRELATION);
    response = ValidStatusResponse();
    response.Header.MessageType = OAC_V5_MESSAGE_RUN_SCAN;
    log.Expect("message type mismatch", OacV5ValidateCorrelation(
        &request.Header, &response.Header) == OAC_V5_INVALID_CORRELATION);
    request = ValidStatusRequest();
    response = ValidStatusResponse();
    request.Header.MessageType = 0;
    response.Header.MessageType = 0;
    log.Expect("invalid equal message types do not correlate",
        OacV5ValidateCorrelation(
            &request.Header, &response.Header) == OAC_V5_INVALID_CORRELATION);

    log.Expect("stable session rule ID", OacV5RuleIdValid(
        OAC_V5_RULE_SESSION_LOST) != FALSE);
    log.Expect("stable driver rule ID", OacV5RuleIdValid(
        OAC_V5_RULE_DRIVER_GATE_TRIP) != FALSE);
    log.Expect("process-image rule uses the process namespace",
        OAC_V5_RULE_PROCESS_IMAGE_LOADED == 0x00020002UL &&
        (OAC_V5_RULE_PROCESS_IMAGE_LOADED & OAC_V5_RULE_GROUP_MASK) ==
            OAC_V5_RULE_PROCESS_BASE);
    log.Expect("CPU rule uses integrity namespace",
        (OAC_V5_RULE_CPU_STATE & OAC_V5_RULE_GROUP_MASK) ==
            OAC_V5_RULE_INTEGRITY_BASE);
    log.Expect("virtualization rule uses platform namespace",
        (OAC_V5_RULE_VIRTUALIZATION & OAC_V5_RULE_GROUP_MASK) ==
            OAC_V5_RULE_PLATFORM_BASE);
    log.Expect("rule zero is invalid", OacV5RuleIdValid(0) == FALSE);
    log.Expect("rule group without code is invalid", OacV5RuleIdValid(
        OAC_V5_RULE_MEMORY_BASE) == FALSE);
    log.Expect("unknown rule group is invalid", OacV5RuleIdValid(
        0x000C0001UL) == FALSE);
    log.Expect("typed alert event", OacV5EventTypeValid(
        OAC_V5_EVENT_POLICY_VIOLATION) != FALSE);
    log.Expect("zero event type is invalid", OacV5EventTypeValid(0) == FALSE);
    log.Expect("future event type is invalid", OacV5EventTypeValid(
        OAC_V5_EVENT_REVOCATION + 1) == FALSE);
    log.Expect("typed observation severity", OacV5ObservationSeverityValid(
        OAC_V5_OBSERVATION_CRITICAL) != FALSE);
    log.Expect("future observation severity is invalid",
        OacV5ObservationSeverityValid(
            OAC_V5_OBSERVATION_CRITICAL + 1) == FALSE);
    log.Expect("policy may be explicitly unevaluated", OacV5PolicySeverityValid(
        OAC_V5_POLICY_NOT_EVALUATED) != FALSE);
    log.Expect("typed policy severity", OacV5PolicySeverityValid(
        OAC_V5_POLICY_CRITICAL) != FALSE);
    log.Expect("future policy severity is invalid", OacV5PolicySeverityValid(
        OAC_V5_POLICY_CRITICAL + 1) == FALSE);
    log.Expect("typed confidence", OacV5ConfidenceValid(
        OAC_V5_CONFIDENCE_HIGH) != FALSE);
    log.Expect("future confidence is invalid", OacV5ConfidenceValid(
        OAC_V5_CONFIDENCE_HIGH + 1) == FALSE);
    log.Expect("typed payload", OacV5PayloadTypeValid(
        OAC_V5_PAYLOAD_BINARY) != FALSE);
    log.Expect("future payload is invalid", OacV5PayloadTypeValid(
        OAC_V5_PAYLOAD_UTF16 + 1) == FALSE);
    log.Expect("typed category", OacV5CategoryValid(
        OAC_V5_CATEGORY_HWID) != FALSE);
    log.Expect("future category is invalid", OacV5CategoryValid(
        OAC_V5_CATEGORY_HWID + 1) == FALSE);
}

void TestSessionTransitions(TestLog& log)
{
    struct Edge
    {
        OAC_V5_SESSION_STATE From;
        OAC_V5_SESSION_STATE To;
    };
    const std::array<Edge, 12> edges =
    {{
        {OAC_V5_SESSION_CLAIMED, OAC_V5_SESSION_LAUNCH_PENDING},
        {OAC_V5_SESSION_CLAIMED, OAC_V5_SESSION_REVOKED},
        {OAC_V5_SESSION_CLAIMED, OAC_V5_SESSION_CLOSING},
        {OAC_V5_SESSION_LAUNCH_PENDING, OAC_V5_SESSION_TARGET_BOUND},
        {OAC_V5_SESSION_LAUNCH_PENDING, OAC_V5_SESSION_REVOKED},
        {OAC_V5_SESSION_LAUNCH_PENDING, OAC_V5_SESSION_CLOSING},
        {OAC_V5_SESSION_TARGET_BOUND, OAC_V5_SESSION_MONITORING},
        {OAC_V5_SESSION_TARGET_BOUND, OAC_V5_SESSION_REVOKED},
        {OAC_V5_SESSION_TARGET_BOUND, OAC_V5_SESSION_CLOSING},
        {OAC_V5_SESSION_MONITORING, OAC_V5_SESSION_REVOKED},
        {OAC_V5_SESSION_MONITORING, OAC_V5_SESSION_CLOSING},
        {OAC_V5_SESSION_REVOKED, OAC_V5_SESSION_CLOSING}
    }};
    bool matrixMatches = true;
    for (OAC_V5_SESSION_STATE from = OAC_V5_SESSION_UNCLAIMED;
         from <= OAC_V5_SESSION_CLOSING;
         ++from)
    {
        for (OAC_V5_SESSION_STATE to = OAC_V5_SESSION_UNCLAIMED;
             to <= OAC_V5_SESSION_CLOSING;
             ++to)
        {
            bool expected = false;
            for (const auto& edge : edges)
            {
                expected = expected || (edge.From == from && edge.To == to);
            }
            matrixMatches = matrixMatches &&
                ((OacV5SessionTransitionValid(from, to) != FALSE) == expected);
        }
    }
    log.Expect("session transition matrix is exact", matrixMatches);
    log.Expect("unclaimed is not a session-object transition",
        OacV5SessionTransitionValid(
            OAC_V5_SESSION_UNCLAIMED,
            OAC_V5_SESSION_CLAIMED) == FALSE);
    log.Expect("out-of-range source state is rejected",
        OacV5SessionTransitionValid(
            OAC_V5_SESSION_CLOSING + 1,
            OAC_V5_SESSION_CLOSING) == FALSE);
    log.Expect("out-of-range destination state is rejected",
        OacV5SessionTransitionValid(
            OAC_V5_SESSION_CLAIMED,
            OAC_V5_SESSION_CLOSING + 1) == FALSE);
    log.Expect("launch cancellation cannot re-arm the session",
        OacV5SessionTransitionValid(
            OAC_V5_SESSION_LAUNCH_PENDING,
            OAC_V5_SESSION_CLAIMED) == FALSE);
}

void TestLaunchDecision(TestLog& log)
{
    constexpr ULONGLONG beforeDeadline = 99;
    constexpr ULONGLONG deadline = 100;

    log.Expect("non-pending candidate is ignored",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_CLAIMED,
            beforeDeadline,
            deadline,
            TRUE,
            TRUE,
            TRUE) == OAC_LAUNCH_IGNORE);
    log.Expect("wrong creator is ignored",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            beforeDeadline,
            deadline,
            FALSE,
            FALSE,
            FALSE) == OAC_LAUNCH_IGNORE);
    log.Expect("service creation after binding is denied",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_TARGET_BOUND,
            beforeDeadline,
            deadline,
            TRUE,
            TRUE,
            TRUE) == OAC_LAUNCH_DENY_SERVICE_CREATION_AFTER_BIND);
    log.Expect("service creation while monitoring is denied",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_MONITORING,
            beforeDeadline,
            deadline,
            TRUE,
            TRUE,
            TRUE) == OAC_LAUNCH_DENY_SERVICE_CREATION_AFTER_BIND);
    log.Expect("candidate at deadline expires",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            deadline,
            deadline,
            TRUE,
            TRUE,
            TRUE) == OAC_LAUNCH_REVOKE_EXPIRED);
    log.Expect("expired decision precedes path decision",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            deadline + 1,
            deadline,
            TRUE,
            FALSE,
            FALSE) == OAC_LAUNCH_REVOKE_EXPIRED);
    log.Expect("missing creation name revokes mismatch",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            beforeDeadline,
            deadline,
            TRUE,
            FALSE,
            TRUE) == OAC_LAUNCH_REVOKE_MISMATCH);
    log.Expect("wrong creation path revokes mismatch",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            beforeDeadline,
            deadline,
            TRUE,
            TRUE,
            FALSE) == OAC_LAUNCH_REVOKE_MISMATCH);
    log.Expect("trusted candidate binds before deadline",
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            beforeDeadline,
            deadline,
            TRUE,
            TRUE,
            TRUE) == OAC_LAUNCH_CONSUME_BIND);

    log.Expect("launch cancellation provenance is valid",
        OacV5RevokeReasonValid(OAC_REVOKE_LAUNCH_CANCELLED) != FALSE);
    log.Expect("launch expiry provenance is valid",
        OacV5RevokeReasonValid(OAC_REVOKE_LAUNCH_EXPIRED) != FALSE);
    log.Expect("launch mismatch provenance is valid",
        OacV5RevokeReasonValid(OAC_REVOKE_LAUNCH_MISMATCH) != FALSE);
    log.Expect("target confirmation provenance is valid",
        OacV5RevokeReasonValid(
            OAC_REVOKE_TARGET_CONFIRMATION_FAILED) != FALSE);
    log.Expect("future revocation provenance is invalid",
        OacV5RevokeReasonValid(
            OAC_REVOKE_TARGET_CONFIRMATION_FAILED + 1) == FALSE);
}

void TestLeasePolicy(TestLog& log)
{
    constexpr uint64_t validUntil = 100;
    constexpr uint64_t graceUntil = 120;

    log.Expect("lease rejects missing deadline",
        OacEvaluateLease(0, 0, 0, 0) == OAC_LEASE_INVALID);
    log.Expect("lease rejects reversed grace period",
        OacEvaluateLease(0, graceUntil, validUntil, 0) == OAC_LEASE_INVALID);
    log.Expect("lease is healthy before its deadline",
        OacEvaluateLease(99, validUntil, graceUntil, 0) == OAC_LEASE_HEALTHY);
    log.Expect("lease enters grace at its deadline",
        OacEvaluateLease(100, validUntil, graceUntil, 0) == OAC_LEASE_DEGRADED);
    log.Expect("lease remains degraded inside grace",
        OacEvaluateLease(119, validUntil, graceUntil, 0) == OAC_LEASE_DEGRADED);
    log.Expect("lease expires at the grace boundary",
        OacEvaluateLease(120, validUntil, graceUntil, 0) == OAC_LEASE_EXPIRED);
    log.Expect("explicit lease revocation wins",
        OacEvaluateLease(1, validUntil, graceUntil, 1) == OAC_LEASE_REVOKED);
    log.Expect("revocation does not depend on a deadline",
        OacEvaluateLease(1, 0, 0, 1) == OAC_LEASE_REVOKED);
    log.Expect("healthy lease keeps the target",
        OacLeaseRequiresTermination(OAC_LEASE_HEALTHY) == 0);
    log.Expect("grace-period lease keeps the target",
        OacLeaseRequiresTermination(OAC_LEASE_DEGRADED) == 0);
    log.Expect("expired lease terminates the target",
        OacLeaseRequiresTermination(OAC_LEASE_EXPIRED) != 0);
    log.Expect("revoked lease terminates the target",
        OacLeaseRequiresTermination(OAC_LEASE_REVOKED) != 0);
    log.Expect("invalid lease terminates the target",
        OacLeaseRequiresTermination(OAC_LEASE_INVALID) != 0);
    log.Expect("unknown lease state terminates the target",
        OacLeaseRequiresTermination(99) != 0);
}

void TestEvidenceTransport(TestLog& log)
{
    auto request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_ALERT);
    log.Expect("valid alert read request", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_EVENT);
    log.Expect("valid event read request", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    log.Expect("null evidence read request", OacValidateEvidenceReadRequest(
        nullptr, sizeof(request)) == OAC_V5_INVALID_POINTER);
    log.Expect("truncated evidence read request", OacValidateEvidenceReadRequest(
        &request, sizeof(request) - 1) == OAC_V5_INVALID_LENGTH);
    log.Expect("oversized evidence read request", OacValidateEvidenceReadRequest(
        &request, sizeof(request) + 1) == OAC_V5_INVALID_LENGTH);

    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_EVENT);
    request.Header.MessageType = OAC_MESSAGE_MANAGE_SNAPSHOT;
    log.Expect("evidence read message identity", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_MESSAGE_TYPE);
    request = ValidEvidenceRequest(0);
    log.Expect("evidence read channel", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_EVENT);
    request.MaximumRecords = 0;
    log.Expect("evidence read requires a page", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request.MaximumRecords = OAC_EVIDENCE_MAX_RECORDS_PER_PAGE + 1;
    log.Expect("evidence read page is bounded", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_EVENT);
    request.AcknowledgeThrough = 1;
    log.Expect("event reads cannot acknowledge", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_ALERT);
    request.AfterSequence = 11;
    request.AcknowledgeThrough = 11;
    log.Expect("alert reads carry acknowledgement", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    request.AcknowledgeThrough = 12;
    log.Expect("alert acknowledgement follows the read cursor",
        OacValidateEvidenceReadRequest(
            &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request.AcknowledgeThrough = 11;
    request.Reserved = 1;
    log.Expect("evidence request reserved field", OacValidateEvidenceReadRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_RESERVED);

    alignas(OAC_EVIDENCE_READ_RESPONSE) EvidenceResponseStorage storage{};
    auto* response = ValidEvidenceResponse(
        storage,
        OAC_EVIDENCE_CHANNEL_EVENT);
    log.Expect("valid event read response", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) == OAC_V5_VALID);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_ALERT);
    log.Expect("valid alert read response", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) == OAC_V5_VALID);
    log.Expect("null evidence response", OacValidateEvidenceReadResponse(
        nullptr, static_cast<ULONG>(storage.size())) ==
            OAC_V5_INVALID_POINTER);
    log.Expect("truncated evidence response", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size() - 1)) ==
            OAC_V5_INVALID_LENGTH);
    response->Header.Size--;
    log.Expect("evidence response stated size", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) ==
            OAC_V5_INVALID_LENGTH);

    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    response->Records[1].Sequence = response->Records[0].Sequence;
    log.Expect("evidence records are strictly ordered",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    ++response->Records[0].Generation;
    log.Expect("evidence records retain session identity",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    response->Records[0].ObservationSeverity = OAC_V5_OBSERVATION_HIGH;
    log.Expect("event channel rejects alert records",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_ALERT);
    response->Records[0].ObservationSeverity = OAC_V5_OBSERVATION_MEDIUM;
    log.Expect("alert channel rejects event records",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);

    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    response->Header.Flags = OAC_V5_RESPONSE_MORE_DATA;
    log.Expect("evidence more-data flag reflects the page",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);
    response->RecordCount = 1;
    response->Header.Size = static_cast<ULONG>(
        offsetof(OAC_EVIDENCE_READ_RESPONSE, Records) +
        sizeof(OAC_V5_EVENT_RECORD));
    log.Expect("valid partial evidence page", OacValidateEvidenceReadResponse(
        response, response->Header.Size) == OAC_V5_VALID);

    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_ALERT);
    response->LossLatched = 1;
    response->DroppedCount = 3;
    response->FirstLostSequence = 12;
    response->LostHighCount = 2;
    response->LostCriticalCount = 1;
    log.Expect("valid alert-loss provenance", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) == OAC_V5_VALID);
    response->DroppedCount = 2;
    log.Expect("alert-loss counters reconcile", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) ==
            OAC_V5_INVALID_VALUE);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_ALERT);
    response->LossLatched = 1;
    response->DroppedCount = 1;
    response->FirstLostSequence = 13;
    response->LostHighCount = 1;
    log.Expect("lost sequence cannot exceed published sequence",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    response->DroppedCount = 1;
    log.Expect("event loss requires a latch", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) ==
            OAC_V5_INVALID_VALUE);
    response->LossLatched = 1;
    response->FirstLostSequence = 11;
    log.Expect("valid event-loss provenance", OacValidateEvidenceReadResponse(
        response, static_cast<ULONG>(storage.size())) == OAC_V5_VALID);
    response->LostHighCount = 1;
    log.Expect("event channel has no alert-loss counters",
        OacValidateEvidenceReadResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);

    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_EVENT);
    request.AfterSequence = 10;
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    log.Expect("valid evidence read correlation",
        OacValidateEvidenceReadCorrelation(
            &request, response) == OAC_V5_VALID);
    log.Expect("null evidence read correlation",
        OacValidateEvidenceReadCorrelation(
            nullptr, response) == OAC_V5_INVALID_POINTER);
    response->Channel = OAC_EVIDENCE_CHANNEL_ALERT;
    log.Expect("evidence correlation binds the channel",
        OacValidateEvidenceReadCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    response->Records[0].Sequence = request.AfterSequence;
    log.Expect("evidence correlation rejects replayed records",
        OacValidateEvidenceReadCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
    request = ValidEvidenceRequest(OAC_EVIDENCE_CHANNEL_ALERT);
    request.AfterSequence = 10;
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_ALERT);
    response->AcknowledgedSequence = 11;
    log.Expect("evidence correlation rejects a stale alert cursor",
        OacValidateEvidenceReadCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
    response = ValidEvidenceResponse(storage, OAC_EVIDENCE_CHANNEL_EVENT);
    request.AfterSequence = 0;
    log.Expect("evidence correlation requires explicit gaps",
        OacValidateEvidenceReadCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
}

void TestSnapshotTransport(TestLog& log)
{
    auto request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_OPEN);
    log.Expect("valid snapshot open request", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_READ);
    request.Cursor = 1;
    log.Expect("valid snapshot read request", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_CLOSE);
    log.Expect("valid snapshot close request", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    log.Expect("null snapshot request", OacValidateSnapshotRequest(
        nullptr, sizeof(request)) == OAC_V5_INVALID_POINTER);
    log.Expect("truncated snapshot request", OacValidateSnapshotRequest(
        &request, sizeof(request) - 1) == OAC_V5_INVALID_LENGTH);
    log.Expect("oversized snapshot request", OacValidateSnapshotRequest(
        &request, sizeof(request) + 1) == OAC_V5_INVALID_LENGTH);

    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_OPEN);
    request.SnapshotId = ValidSnapshotId();
    log.Expect("snapshot open requires a zero ID", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_READ);
    request.SnapshotId = {};
    log.Expect("snapshot read requires an ID", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_READ);
    request.MaximumRecords = OAC_SNAPSHOT_MAX_RECORDS_PER_PAGE + 1;
    log.Expect("snapshot page is bounded", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_CLOSE);
    request.Cursor = 1;
    log.Expect("snapshot close has no cursor", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_OPEN);
    request.SnapshotType = 0;
    log.Expect("snapshot type is explicit", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_OPEN);
    request.Reserved = 1;
    log.Expect("snapshot request reserved field", OacValidateSnapshotRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_RESERVED);

    auto record = ValidSnapshotRecord(0);
    log.Expect("valid snapshot record", OacValidateSnapshotRecord(
        &record, sizeof(record)) == OAC_V5_VALID);
    log.Expect("null snapshot record", OacValidateSnapshotRecord(
        nullptr, sizeof(record)) == OAC_V5_INVALID_POINTER);
    record = ValidSnapshotRecord(0);
    record.Address = 0;
    log.Expect("snapshot record requires an address", OacValidateSnapshotRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidSnapshotRecord(0);
    record.Name[record.NameLength + 1] = L'X';
    log.Expect("snapshot record rejects a dirty name tail",
        OacValidateSnapshotRecord(
            &record, sizeof(record)) == OAC_V5_INVALID_RESERVED);
    record = ValidSnapshotRecord(0);
    record.RecordType = 0;
    log.Expect("snapshot record type is explicit", OacValidateSnapshotRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);

    alignas(OAC_SNAPSHOT_RESPONSE) SnapshotResponseStorage storage{};
    auto* response = ValidSnapshotResponse(storage);
    log.Expect("valid ready snapshot response", OacValidateSnapshotResponse(
        response, static_cast<ULONG>(storage.size())) == OAC_V5_VALID);
    log.Expect("null snapshot response", OacValidateSnapshotResponse(
        nullptr, static_cast<ULONG>(storage.size())) ==
            OAC_V5_INVALID_POINTER);
    log.Expect("truncated snapshot response", OacValidateSnapshotResponse(
        response, static_cast<ULONG>(storage.size() - 1)) ==
            OAC_V5_INVALID_LENGTH);
    response = ValidSnapshotResponse(storage);
    response->Records[1].Index = 2;
    log.Expect("snapshot records follow the cursor", OacValidateSnapshotResponse(
        response, static_cast<ULONG>(storage.size())) ==
            OAC_V5_INVALID_VALUE);
    response = ValidSnapshotResponse(storage);
    response->RecordCount = 1;
    response->NextCursor = 1;
    response->Header.Size = static_cast<ULONG>(
        offsetof(OAC_SNAPSHOT_RESPONSE, Records) +
        sizeof(OAC_SNAPSHOT_RECORD));
    response->Header.Flags = OAC_V5_RESPONSE_MORE_DATA;
    log.Expect("valid snapshot page with more data", OacValidateSnapshotResponse(
        response, response->Header.Size) == OAC_V5_VALID);
    response->Header.Flags = 0;
    log.Expect("snapshot more-data flag is mandatory",
        OacValidateSnapshotResponse(
            response, response->Header.Size) == OAC_V5_INVALID_VALUE);
    response = ValidSnapshotResponse(storage);
    response->NextCursor = 1;
    log.Expect("snapshot cursor advance matches record count",
        OacValidateSnapshotResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);
    response = ValidSnapshotResponse(storage);
    response->Truncated = 1;
    log.Expect("snapshot truncation matches available count",
        OacValidateSnapshotResponse(
            response, static_cast<ULONG>(storage.size())) ==
                OAC_V5_INVALID_VALUE);

    response = ValidSnapshotResponse(storage);
    response->Header.Size = static_cast<ULONG>(
        offsetof(OAC_SNAPSHOT_RESPONSE, Records));
    response->State = OAC_SNAPSHOT_STATE_FAILED;
    response->TotalItems = 0;
    response->AvailableItems = 0;
    response->RecordCount = 0;
    response->NextCursor = 0;
    response->FailureStatus = static_cast<LONG>(0xc0000001UL);
    log.Expect("valid failed snapshot response", OacValidateSnapshotResponse(
        response, response->Header.Size) == OAC_V5_VALID);
    response->FailureStatus = 0;
    log.Expect("failed snapshot carries a status", OacValidateSnapshotResponse(
        response, response->Header.Size) == OAC_V5_INVALID_VALUE);

    response = ValidSnapshotResponse(storage);
    response->Header.Size = static_cast<ULONG>(
        offsetof(OAC_SNAPSHOT_RESPONSE, Records));
    response->State = OAC_SNAPSHOT_STATE_CLOSED;
    response->RecordCount = 0;
    response->NextCursor = 0;
    log.Expect("valid closed snapshot response", OacValidateSnapshotResponse(
        response, response->Header.Size) == OAC_V5_VALID);
    response->FailureStatus = static_cast<LONG>(0xc0000001UL);
    log.Expect("closed snapshot clears failure state",
        OacValidateSnapshotResponse(
            response, response->Header.Size) == OAC_V5_INVALID_VALUE);

    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_OPEN);
    response = ValidSnapshotResponse(storage);
    log.Expect("valid snapshot open correlation",
        OacValidateSnapshotCorrelation(
            &request, response) == OAC_V5_VALID);
    log.Expect("null snapshot correlation",
        OacValidateSnapshotCorrelation(
            nullptr, response) == OAC_V5_INVALID_POINTER);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_READ);
    log.Expect("valid snapshot read correlation",
        OacValidateSnapshotCorrelation(
            &request, response) == OAC_V5_VALID);
    ++response->CursorGeneration;
    log.Expect("snapshot correlation binds cursor generation",
        OacValidateSnapshotCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
    response = ValidSnapshotResponse(storage);
    response->Cursor = 1;
    log.Expect("snapshot correlation binds the requested cursor",
        OacValidateSnapshotCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
    request = ValidSnapshotRequest(OAC_SNAPSHOT_OPERATION_CLOSE);
    response = ValidSnapshotResponse(storage);
    response->Header.Size = static_cast<ULONG>(
        offsetof(OAC_SNAPSHOT_RESPONSE, Records));
    response->State = OAC_SNAPSHOT_STATE_CLOSED;
    response->RecordCount = 0;
    response->NextCursor = 0;
    log.Expect("valid snapshot close correlation",
        OacValidateSnapshotCorrelation(
            &request, response) == OAC_V5_VALID);
    response->SnapshotId.Low++;
    log.Expect("snapshot close binds the snapshot ID",
        OacValidateSnapshotCorrelation(
            &request, response) == OAC_V5_INVALID_CORRELATION);
}

void TestLabEvidenceContract(TestLog& log)
{
    OAC_TEST_INJECT_EVIDENCE_REQUEST request{};
    FillSessionHeader(
        request.Header,
        sizeof(request),
        OAC_TEST_MESSAGE_INJECT_EVIDENCE);
    request.TestVersion = OAC_TEST_PROTOCOL_VERSION;
    request.Count = 1;
    request.RuleId = OAC_V5_RULE_KERNEL_IMAGE_LOADED;
    request.EventType = OAC_V5_EVENT_OBSERVATION;
    request.ObservationSeverity = OAC_V5_OBSERVATION_INFO;
    request.PolicySeverity = OAC_V5_POLICY_NOT_EVALUATED;
    request.Confidence = OAC_V5_CONFIDENCE_HIGH;
    request.Category = OAC_V5_CATEGORY_DRIVER;
    request.EvidenceFlags = OAC_V5_EVIDENCE_KERNEL_SOURCE;
    log.Expect("valid lab evidence injection", OacValidateTestEvidenceRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    log.Expect("null lab evidence injection", OacValidateTestEvidenceRequest(
        nullptr, sizeof(request)) == OAC_V5_INVALID_POINTER);
    request.Count = OAC_TEST_MAX_INJECTED_RECORDS;
    log.Expect("maximum lab evidence batch", OacValidateTestEvidenceRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    request.Count++;
    log.Expect("lab evidence batch is bounded", OacValidateTestEvidenceRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request.Count = 1;
    request.TestVersion++;
    log.Expect("lab test protocol is exact", OacValidateTestEvidenceRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request.TestVersion = OAC_TEST_PROTOCOL_VERSION;
    request.EventType = OAC_V5_EVENT_POLICY_VIOLATION;
    log.Expect("lab policy violation must be evaluated",
        OacValidateTestEvidenceRequest(
            &request, sizeof(request)) == OAC_V5_INVALID_VALUE);
    request.PolicySeverity = OAC_V5_POLICY_HIGH;
    log.Expect("valid lab policy alert", OacValidateTestEvidenceRequest(
        &request, sizeof(request)) == OAC_V5_VALID);
    request.Reserved = 1;
    log.Expect("lab request reserved field", OacValidateTestEvidenceRequest(
        &request, sizeof(request)) == OAC_V5_INVALID_RESERVED);
}

void TestEventRecords(TestLog& log)
{
    auto record = ValidEventRecord();
    log.Expect("valid event without payload", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);
    log.Expect("null event record", OacV5ValidateEventRecord(
        nullptr, sizeof(record)) == OAC_V5_INVALID_POINTER);
    log.Expect("truncated event record", OacV5ValidateEventRecord(
        &record, sizeof(record) - 1) == OAC_V5_INVALID_LENGTH);
    log.Expect("oversized event record", OacV5ValidateEventRecord(
        &record, sizeof(record) + 1) == OAC_V5_INVALID_LENGTH);

    record = ValidEventRecord();
    --record.Size;
    log.Expect("event stated size", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_LENGTH);
    record = ValidEventRecord();
    --record.Version;
    log.Expect("event protocol version", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VERSION);
    record = ValidEventRecord();
    record.RuleId = 0;
    log.Expect("event zero rule ID", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.EventType = 0;
    log.Expect("event unknown type", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.ObservationSeverity = OAC_V5_OBSERVATION_CRITICAL + 1;
    log.Expect("event observation severity", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.PolicySeverity = OAC_V5_POLICY_CRITICAL + 1;
    log.Expect("event policy severity", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.EventType = OAC_V5_EVENT_POLICY_VIOLATION;
    log.Expect("policy violation must be evaluated", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record.PolicySeverity = OAC_V5_POLICY_HIGH;
    log.Expect("evaluated policy violation", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);
    record = ValidEventRecord();
    record.Confidence = OAC_V5_CONFIDENCE_HIGH + 1;
    log.Expect("event confidence", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.Category = OAC_V5_CATEGORY_HWID + 1;
    log.Expect("event category", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16 + 1;
    log.Expect("event payload type", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.Reserved = 1;
    log.Expect("event reserved field", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_RESERVED);

    record = ValidEventRecord();
    record.SessionId = {};
    log.Expect("event zero session", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_SESSION);
    record = ValidEventRecord();
    record.Generation = 0;
    log.Expect("event zero generation", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_GENERATION);
    record = ValidEventRecord();
    record.EvidenceFlags |= 0x8000000000000000ULL;
    log.Expect("event unknown evidence flag", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_FLAGS);
    record = ValidEventRecord();
    record.Flags = 1;
    log.Expect("event unknown record flag", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_FLAGS);

    record = ValidEventRecord();
    record.Sequence = 0;
    log.Expect("event zero sequence", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.Timestamp100ns = 0;
    log.Expect("event zero timestamp", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.OccurrenceCount = 0;
    log.Expect("event zero occurrence count", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.FirstOccurrence100ns = 101;
    log.Expect("event first occurrence after source timestamp",
        OacV5ValidateEventRecord(
            &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.LastOccurrence100ns = 99;
    log.Expect("event last occurrence before source timestamp",
        OacV5ValidateEventRecord(
            &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.IngestionTimestamp100ns = 101;
    log.Expect("event incomplete service provenance", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.ServiceSequence = 1;
    log.Expect("event service sequence without ingestion time",
        OacV5ValidateEventRecord(
            &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.IngestionTimestamp100ns = 99;
    record.ServiceSequence = 1;
    log.Expect("event ingestion predates source", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record.IngestionTimestamp100ns = 101;
    log.Expect("valid service provenance", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);

    record = ValidEventRecord();
    record.PayloadLength = 1;
    log.Expect("none payload has zero length", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_LENGTH);
    record = ValidEventRecord();
    record.Text[0] = L'X';
    log.Expect("none payload rejects hidden bytes", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_RESERVED);

    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_BINARY;
    log.Expect("binary payload cannot be empty", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_LENGTH);
    record.PayloadLength = 3;
    auto* bytes = reinterpret_cast<UCHAR*>(record.Text);
    bytes[0] = 0x10;
    bytes[1] = 0x20;
    bytes[2] = 0x30;
    log.Expect("valid binary payload", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);
    bytes[3] = 0x40;
    log.Expect("binary payload rejects dirty tail", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_RESERVED);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_BINARY;
    record.PayloadLength = sizeof(record.Text) + 1;
    log.Expect("binary payload bounds", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_RANGE);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_BINARY;
    record.PayloadLength = sizeof(record.Text);
    std::memset(record.Text, 0x5A, sizeof(record.Text));
    log.Expect("full binary payload", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);

    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16;
    record.Text[0] = L'O';
    record.Text[1] = L'K';
    record.Text[2] = L'\0';
    record.PayloadLength = 3 * sizeof(WCHAR);
    log.Expect("valid UTF-16 payload", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);
    record.PayloadLength = 3;
    log.Expect("odd UTF-16 payload length", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_ALIGNMENT);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16;
    record.Text[0] = L'X';
    record.PayloadLength = sizeof(WCHAR);
    log.Expect("UTF-16 payload requires terminator", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16;
    record.Text[0] = L'A';
    record.Text[1] = L'\0';
    record.Text[2] = L'B';
    record.Text[3] = L'\0';
    record.PayloadLength = 4 * sizeof(WCHAR);
    log.Expect("UTF-16 payload rejects embedded null", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16;
    record.Text[0] = static_cast<WCHAR>(0xD800);
    record.Text[1] = L'\0';
    record.PayloadLength = 2 * sizeof(WCHAR);
    log.Expect("UTF-16 payload rejects unpaired high surrogate",
        OacV5ValidateEventRecord(
            &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record.Text[0] = static_cast<WCHAR>(0xDC00);
    log.Expect("UTF-16 payload rejects unpaired low surrogate",
        OacV5ValidateEventRecord(
            &record, sizeof(record)) == OAC_V5_INVALID_VALUE);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16;
    record.Text[0] = static_cast<WCHAR>(0xD83D);
    record.Text[1] = static_cast<WCHAR>(0xDE00);
    record.Text[2] = L'\0';
    record.PayloadLength = 3 * sizeof(WCHAR);
    log.Expect("valid UTF-16 surrogate pair", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_VALID);
    record = ValidEventRecord();
    record.PayloadType = OAC_V5_PAYLOAD_UTF16;
    record.Text[0] = L'A';
    record.Text[1] = L'\0';
    record.Text[2] = L'X';
    record.PayloadLength = 2 * sizeof(WCHAR);
    log.Expect("UTF-16 payload rejects dirty tail", OacV5ValidateEventRecord(
        &record, sizeof(record)) == OAC_V5_INVALID_RESERVED);
}

OAC_V5_EVENT_RECORD PolicyObservation(
    OAC_V5_RULE_ID ruleId,
    OAC_V5_CATEGORY category,
    OAC_V5_OBSERVATION_SEVERITY severity,
    ULONGLONG evidenceFlags)
{
    auto record = ValidEventRecord();
    record.RuleId = ruleId;
    record.Category = category;
    record.ObservationSeverity = severity;
    record.EvidenceFlags = evidenceFlags;
    return record;
}

OAC_POLICY_SIGNER_CLASSIFICATION SignedClassification(uint32_t flags)
{
    OAC_POLICY_SIGNER_CLASSIFICATION signer{};
    signer.SignatureSource = OAC_POLICY_SIGNATURE_EMBEDDED;
    signer.ChainState = OAC_POLICY_CHAIN_VALID;
    signer.RevocationState = OAC_POLICY_REVOCATION_GOOD;
    signer.TimestampState = OAC_POLICY_TIMESTAMP_VALID;
    signer.Flags = flags;
    signer.ThumbprintLength = 20;
    for (uint32_t index = 0; index < signer.ThumbprintLength; ++index)
        signer.Thumbprint[index] = static_cast<uint8_t>(index + 1);
    return signer;
}

void TestPolicyCatalog(TestLog& log)
{
    size_t count = 0;
    const OAC_POLICY_RULE* rules = OacPolicyRuleCatalog(&count);
    log.Expect("policy catalog is available", rules != nullptr);
    log.Expect("policy catalog has exact rule count",
        count == OAC_POLICY_RULE_COUNT);
    log.Expect("policy catalog requires count output",
        OacPolicyRuleCatalog(nullptr) == nullptr);

    bool valid = rules != nullptr && count == OAC_POLICY_RULE_COUNT;
    for (size_t index = 0; valid && index < count; ++index)
    {
        const auto& rule = rules[index];
        valid = OacV5RuleIdValid(rule.RuleId) != FALSE &&
            OacV5EventTypeValid(rule.EventType) != FALSE &&
            OacV5CategoryValid(rule.Category) != FALSE &&
            OacV5ObservationSeverityValid(
                rule.MinimumObservationSeverity) != FALSE &&
            OacV5ObservationSeverityValid(
                rule.MaximumObservationSeverity) != FALSE &&
            rule.MinimumObservationSeverity <=
                rule.MaximumObservationSeverity &&
            OacPolicyConfidenceValid(rule.Confidence) != 0 &&
            OacPolicyActionValid(rule.ObserveAction) != 0 &&
            OacPolicyActionValid(rule.EnforceAction) != 0 &&
            OacPolicyActionValid(rule.StrictAction) != 0 &&
            (rule.RequiredEvidenceFlags & ~OAC_V5_EVIDENCE_FLAGS) == 0 &&
            (rule.Flags & ~OAC_POLICY_RULE_FLAGS) == 0 &&
            rule.Reserved == 0 &&
            (index == 0 || rules[index - 1].RuleId < rule.RuleId);
    }
    log.Expect("policy catalog is sorted and typed", valid);

    bool allModesEvaluate = valid;
    constexpr OAC_POLICY_MODE modes[] = {
        OAC_POLICY_MODE_OBSERVE,
        OAC_POLICY_MODE_ENFORCE,
        OAC_POLICY_MODE_STRICT
    };
    for (size_t index = 0; allModesEvaluate && index < count; ++index)
    {
        auto observation = PolicyObservation(
            rules[index].RuleId,
            rules[index].Category,
            rules[index].MinimumObservationSeverity,
            rules[index].RequiredEvidenceFlags);
        observation.EventType = rules[index].EventType;
        for (const auto mode : modes)
        {
            OAC_POLICY_DECISION decision{};
            if (!OacPolicyEvaluate(mode, &observation, nullptr, &decision) ||
                decision.RuleId != rules[index].RuleId ||
                !OacPolicyActionValid(decision.Action) ||
                !OacPolicyConfidenceValid(decision.Confidence) ||
                !OacV5PolicySeverityValid(decision.PolicySeverity))
            {
                allModesEvaluate = false;
                break;
            }
        }
    }
    log.Expect("every policy rule evaluates in every deployment mode",
        allModesEvaluate);
    log.Expect("policy catalog stable first rule",
        rules != nullptr && rules[0].RuleId == OAC_V5_RULE_SESSION_CLAIMED);
    log.Expect("policy catalog stable last rule",
        rules != nullptr &&
        rules[count - 1].RuleId == OAC_V5_RULE_VIRTUALIZATION);

    log.Expect("policy deployment modes",
        OacPolicyModeValid(OAC_POLICY_MODE_OBSERVE) != 0 &&
        OacPolicyModeValid(OAC_POLICY_MODE_ENFORCE) != 0 &&
        OacPolicyModeValid(OAC_POLICY_MODE_STRICT) != 0 &&
        OacPolicyModeValid(0) == 0 &&
        OacPolicyModeValid(OAC_POLICY_MODE_STRICT + 1) == 0);
    log.Expect("policy action range",
        OacPolicyActionValid(OAC_POLICY_ACTION_NO_ACTION) != 0 &&
        OacPolicyActionValid(OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW) != 0 &&
        OacPolicyActionValid(OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW + 1) == 0);
    log.Expect("policy confidence range",
        OacPolicyConfidenceValid(OAC_POLICY_CONFIDENCE_INFORMATIONAL) != 0 &&
        OacPolicyConfidenceValid(
            OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY) != 0 &&
        OacPolicyConfidenceValid(
            OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY + 1) == 0);
}

void TestSignerClassification(TestLog& log)
{
    OAC_POLICY_SIGNER_CLASSIFICATION signer{};
    log.Expect("unavailable signer classification",
        OacPolicySignerClassificationValid(&signer) != 0);
    log.Expect("null signer classification",
        OacPolicySignerClassificationValid(nullptr) == 0);

    signer.SignatureSource = OAC_POLICY_SIGNATURE_UNSIGNED;
    signer.ChainState = OAC_POLICY_CHAIN_NOT_CHECKED;
    signer.RevocationState = OAC_POLICY_REVOCATION_NOT_CHECKED;
    signer.TimestampState = OAC_POLICY_TIMESTAMP_MISSING;
    log.Expect("unsigned signer classification",
        OacPolicySignerClassificationValid(&signer) != 0);

    signer = SignedClassification(OAC_POLICY_SIGNER_APPROVED_FILE);
    log.Expect("approved exact signer classification",
        OacPolicySignerClassificationValid(&signer) != 0);
    auto catalogSigner = signer;
    catalogSigner.SignatureSource = OAC_POLICY_SIGNATURE_CATALOG;
    catalogSigner.ThumbprintLength = 32;
    for (uint32_t index = 20; index < catalogSigner.ThumbprintLength; ++index)
        catalogSigner.Thumbprint[index] = static_cast<uint8_t>(index + 1);
    log.Expect("catalog signer classification",
        OacPolicySignerClassificationValid(&catalogSigner) != 0);
    auto invalid = signer;
    invalid.ThumbprintLength = 0;
    log.Expect("signed classification requires identity",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    std::fill(
        std::begin(invalid.Thumbprint),
        std::end(invalid.Thumbprint),
        uint8_t{0});
    log.Expect("signed classification rejects an empty identity",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    invalid.Thumbprint[20] = 1;
    log.Expect("signer classification rejects dirty identity tail",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    invalid.Flags |= 0x80000000u;
    log.Expect("signer classification rejects unknown flags",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    invalid.ChainState = OAC_POLICY_CHAIN_INVALID;
    log.Expect("approved signer requires a valid chain",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    invalid.RevocationState = OAC_POLICY_REVOCATION_REVOKED;
    log.Expect("revoked signer cannot remain approved",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    invalid.Reserved[1] = 1;
    log.Expect("signer classification reserved fields",
        OacPolicySignerClassificationValid(&invalid) == 0);
    invalid = signer;
    invalid.SignatureSource = OAC_POLICY_SIGNATURE_CATALOG + 1;
    log.Expect("signer classification source range",
        OacPolicySignerClassificationValid(&invalid) == 0);
}

void TestPolicyEvaluation(TestLog& log)
{
    constexpr ULONGLONG callbackEvidence = OAC_V5_EVIDENCE_KERNEL_SOURCE |
        OAC_V5_EVIDENCE_CALLBACK_SOURCE;
    auto gate = PolicyObservation(
        OAC_V5_RULE_DRIVER_GATE_TRIP,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_CRITICAL,
        callbackEvidence);
    gate.Confidence = OAC_V5_CONFIDENCE_LOW;
    OAC_POLICY_DECISION decision{};
    log.Expect("observe mode records a gate trip",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_OBSERVE, &gate, nullptr, &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_RECORD &&
        decision.Confidence ==
            OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY &&
        decision.PolicySeverity == OAC_V5_POLICY_INFO);
    log.Expect("enforce mode revokes a gate trip",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE, &gate, nullptr, &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REVOKE_SESSION &&
        decision.PolicySeverity == OAC_V5_POLICY_CRITICAL);
    log.Expect("strict mode revokes a gate trip",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_STRICT, &gate, nullptr, &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REVOKE_SESSION);

    auto evaluated = gate;
    log.Expect("policy decision enriches observation",
        OacPolicyApplyDecision(&evaluated, &decision) != 0 &&
        evaluated.EventType == OAC_V5_EVENT_POLICY_VIOLATION &&
        evaluated.PolicySeverity == OAC_V5_POLICY_CRITICAL &&
        evaluated.Confidence == gate.Confidence);

    gate.PayloadType = OAC_V5_PAYLOAD_UTF16;
    gate.Text[0] = L'A';
    gate.Text[1] = L'\0';
    gate.PayloadLength = 2 * sizeof(WCHAR);
    auto renamed = gate;
    renamed.Text[0] = L'B';
    OAC_POLICY_DECISION first{};
    OAC_POLICY_DECISION second{};
    log.Expect("display text has no policy meaning",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE, &gate, nullptr, &first) != 0 &&
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE, &renamed, nullptr, &second) != 0 &&
        std::memcmp(&first, &second, sizeof(first)) == 0);

    constexpr OAC_POLICY_DECISION sentinel{
        0x11223344u,
        0x55667788u,
        0x99AABBCCu,
        0xDDEEFF00u
    };
    auto invalidObservation = gate;
    invalidObservation.RuleId = OAC_V5_RULE_POLICY_BASE + 1;
    decision = sentinel;
    log.Expect("unknown catalog rule is rejected",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &invalidObservation,
            nullptr,
            &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);
    invalidObservation = gate;
    invalidObservation.EventType = OAC_V5_EVENT_SESSION_STATE_CHANGED;
    decision = sentinel;
    log.Expect("policy rejects event type drift",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &invalidObservation,
            nullptr,
            &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);
    invalidObservation = gate;
    invalidObservation.Category = OAC_V5_CATEGORY_MODULE;
    decision = sentinel;
    log.Expect("policy rejects category drift",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &invalidObservation,
            nullptr,
            &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);
    invalidObservation = gate;
    invalidObservation.ObservationSeverity = OAC_V5_OBSERVATION_HIGH;
    decision = sentinel;
    log.Expect("policy rejects observation severity drift",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &invalidObservation,
            nullptr,
            &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);
    invalidObservation = gate;
    invalidObservation.EvidenceFlags = OAC_V5_EVIDENCE_KERNEL_SOURCE;
    decision = sentinel;
    log.Expect("policy requires typed provenance",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &invalidObservation,
            nullptr,
            &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);
    invalidObservation = gate;
    invalidObservation.PolicySeverity = OAC_V5_POLICY_HIGH;
    decision = sentinel;
    log.Expect("collector cannot pre-label policy",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &invalidObservation,
            nullptr,
            &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);

    auto signer = SignedClassification(OAC_POLICY_SIGNER_APPROVED_FILE);
    decision = sentinel;
    log.Expect("unrelated rules reject signer metadata",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE, &gate, &signer, &decision) == 0 &&
        std::memcmp(&decision, &sentinel, sizeof(decision)) == 0);

    auto kernelImage = PolicyObservation(
        OAC_V5_RULE_KERNEL_IMAGE_LOADED,
        OAC_V5_CATEGORY_DRIVER,
        OAC_V5_OBSERVATION_MEDIUM,
        callbackEvidence);
    log.Expect("unknown signer requires corroboration",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &kernelImage,
            nullptr,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_CORROBORATE &&
        decision.Confidence == OAC_POLICY_CONFIDENCE_MODERATE);
    log.Expect("strict driver-load policy revokes",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_STRICT,
            &kernelImage,
            nullptr,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REVOKE_SESSION);

    OAC_POLICY_SIGNER_CLASSIFICATION unsignedSigner{};
    unsignedSigner.SignatureSource = OAC_POLICY_SIGNATURE_UNSIGNED;
    unsignedSigner.ChainState = OAC_POLICY_CHAIN_NOT_CHECKED;
    unsignedSigner.RevocationState = OAC_POLICY_REVOCATION_NOT_CHECKED;
    unsignedSigner.TimestampState = OAC_POLICY_TIMESTAMP_MISSING;
    log.Expect("unsigned driver requests server review",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &kernelImage,
            &unsignedSigner,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW &&
        decision.Confidence == OAC_POLICY_CONFIDENCE_STRONG);

    log.Expect("approved exact driver is recorded",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &kernelImage,
            &signer,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_RECORD &&
        decision.Confidence == OAC_POLICY_CONFIDENCE_STRONG);
    signer = SignedClassification(OAC_POLICY_SIGNER_APPROVED_PUBLISHER);
    log.Expect("approved publisher is recorded",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &kernelImage,
            &signer,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_RECORD &&
        decision.Confidence == OAC_POLICY_CONFIDENCE_MODERATE);
    signer.RevocationState = OAC_POLICY_REVOCATION_UNAVAILABLE;
    log.Expect("unavailable revocation requires corroboration",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &kernelImage,
            &signer,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_CORROBORATE);
    signer = SignedClassification(0);
    signer.TimestampState = OAC_POLICY_TIMESTAMP_INVALID;
    log.Expect("invalid timestamp requests review",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &kernelImage,
            &signer,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW);

    auto cpu = PolicyObservation(
        OAC_V5_RULE_CPU_STATE,
        OAC_V5_CATEGORY_INTEGRITY,
        OAC_V5_OBSERVATION_MEDIUM,
        OAC_V5_EVIDENCE_KERNEL_SOURCE);
    log.Expect("CPU state is corroborated in enforce mode",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE, &cpu, nullptr, &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_CORROBORATE &&
        decision.Confidence == OAC_POLICY_CONFIDENCE_WEAK);
    cpu.EvidenceFlags |= OAC_V5_EVIDENCE_INCOMPLETE;
    log.Expect("incomplete evidence requests review",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE, &cpu, nullptr, &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW &&
        decision.Confidence == OAC_POLICY_CONFIDENCE_STRONG);

    auto sessionLoss = PolicyObservation(
        OAC_V5_RULE_SESSION_LOST,
        OAC_V5_CATEGORY_SERVICE,
        OAC_V5_OBSERVATION_CRITICAL,
        OAC_V5_EVIDENCE_KERNEL_SOURCE);
    sessionLoss.EventType = OAC_V5_EVENT_REVOCATION;
    log.Expect("session loss is a conclusive revoke",
        OacPolicyEvaluate(
            OAC_POLICY_MODE_ENFORCE,
            &sessionLoss,
            nullptr,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_REVOKE_SESSION &&
        OacPolicyApplyDecision(&sessionLoss, &decision) != 0 &&
        sessionLoss.EventType == OAC_V5_EVENT_REVOCATION &&
        sessionLoss.PolicySeverity == OAC_V5_POLICY_CRITICAL);

    auto before = gate;
    OAC_POLICY_DECISION mismatched = decision;
    mismatched.RuleId = OAC_V5_RULE_SESSION_LOST;
    log.Expect("policy application preserves mismatched record",
        OacPolicyApplyDecision(&gate, &mismatched) == 0 &&
        std::memcmp(&gate, &before, sizeof(gate)) == 0);

    mismatched = first;
    mismatched.PolicySeverity = OAC_V5_POLICY_LOW;
    before = gate;
    log.Expect("policy application rejects inconsistent action severity",
        OacPolicyApplyDecision(&gate, &mismatched) == 0 &&
        std::memcmp(&gate, &before, sizeof(gate)) == 0);
    mismatched = first;
    mismatched.Confidence =
        OAC_POLICY_CONFIDENCE_CONCLUSIVE_FOR_LOCAL_POLICY + 1;
    before = gate;
    log.Expect("policy application rejects invalid confidence",
        OacPolicyApplyDecision(&gate, &mismatched) == 0 &&
        std::memcmp(&gate, &before, sizeof(gate)) == 0);

    OAC_POLICY_DECISION denyLaunch{
        gate.RuleId,
        OAC_POLICY_ACTION_DENY_LAUNCH,
        OAC_POLICY_CONFIDENCE_STRONG,
        OAC_V5_POLICY_CRITICAL
    };
    before = gate;
    log.Expect("deny-launch action produces a policy violation",
        OacPolicyApplyDecision(&gate, &denyLaunch) != 0 &&
        gate.EventType == OAC_V5_EVENT_POLICY_VIOLATION &&
        gate.PolicySeverity == OAC_V5_POLICY_CRITICAL &&
        gate.Confidence == before.Confidence);
}

OAC_GAME_MANIFEST ValidGameManifest()
{
    OAC_GAME_MANIFEST manifest{};
    constexpr std::array<uint8_t, OAC_MANIFEST_MAGIC_SIZE> magic{
        'O', 'A', 'C', 'G', 'M', 'A', 'N', 0
    };
    constexpr char16_t executableName[] = u"Game.exe";

    std::copy(magic.begin(), magic.end(), manifest.Magic);
    manifest.SchemaVersion = OAC_MANIFEST_SCHEMA;
    manifest.Size = sizeof(manifest);
    manifest.ExecutableNameLength =
        static_cast<uint32_t>(std::size(executableName) - 1);
    for (size_t index = 0; index != OAC_MANIFEST_ID_SIZE; ++index)
    {
        manifest.ManifestId[index] = static_cast<uint8_t>(index + 1);
        manifest.GameId[index] = static_cast<uint8_t>(index + 17);
        manifest.BuildId[index] = static_cast<uint8_t>(index + 33);
    }
    manifest.Sequence = 7;
    manifest.IssuedAtUnixSeconds = 999900;
    manifest.ExpiresAtUnixSeconds = 1086400;
    manifest.ExecutableSize = 4096;
    manifest.RequiredDriverProtocol = OAC_V5_VERSION;
    manifest.RequiredServiceProtocol = OAC_IPC_PROTOCOL_REVISION;
    manifest.RequiredLauncherProtocol = OAC_IPC_PROTOCOL_REVISION;
    for (size_t index = 0; index != OAC_MANIFEST_HASH_SIZE; ++index)
    {
        manifest.ExecutableSha256[index] = static_cast<uint8_t>(index + 1);
        manifest.SigningKeyId[index] = static_cast<uint8_t>(index + 65);
    }
    for (size_t index = 0; index != std::size(executableName) - 1; ++index)
    {
        manifest.ExecutableName[index] =
            static_cast<uint16_t>(executableName[index]);
    }
    return manifest;
}

void TestGameManifest(TestLog& log)
{
    constexpr uint64_t now = 1000000;
    auto manifest = ValidGameManifest();
    const auto validate = [&manifest](uint64_t currentTime) {
        return OacManifestValidate(
            &manifest,
            sizeof(manifest),
            currentTime,
            OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION,
            OAC_IPC_PROTOCOL_REVISION);
    };

    log.Expect("valid canonical game manifest", validate(now) == OAC_MANIFEST_VALID);
    log.Expect("manifest null pointer",
        OacManifestValidate(
            nullptr,
            sizeof(manifest),
            now,
            OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION,
            OAC_IPC_PROTOCOL_REVISION) == OAC_MANIFEST_INVALID_POINTER);
    log.Expect("manifest exact length",
        OacManifestValidate(
            &manifest,
            sizeof(manifest) - 1,
            now,
            OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION,
            OAC_IPC_PROTOCOL_REVISION) == OAC_MANIFEST_INVALID_LENGTH);

    auto invalid = manifest;
    invalid.Magic[0] ^= 1;
    log.Expect("manifest magic", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_MAGIC);
    invalid = manifest;
    ++invalid.SchemaVersion;
    log.Expect("manifest schema", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_SCHEMA);
    invalid = manifest;
    --invalid.Size;
    log.Expect("manifest stated size", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_SCHEMA);
    invalid = manifest;
    invalid.Flags = 1;
    log.Expect("manifest flags", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_RESERVED);
    invalid = manifest;
    invalid.Reserved0 = 1;
    log.Expect("manifest scalar reserved field", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_RESERVED);
    invalid = manifest;
    invalid.Reserved[71] = 1;
    log.Expect("manifest reserved tail", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_RESERVED);

    invalid = manifest;
    std::fill(
        std::begin(invalid.ManifestId),
        std::end(invalid.ManifestId),
        uint8_t{0});
    log.Expect("manifest nonzero identity", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_IDENTITY);
    invalid = manifest;
    invalid.Sequence = 0;
    log.Expect("manifest nonzero sequence", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_IDENTITY);

    invalid = manifest;
    invalid.IssuedAtUnixSeconds = now + OAC_MANIFEST_CLOCK_SKEW_SECONDS + 1;
    log.Expect("manifest future issuance", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_TIME);
    invalid = manifest;
    invalid.ExpiresAtUnixSeconds = invalid.IssuedAtUnixSeconds;
    log.Expect("manifest ordered lifetime", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_TIME);
    invalid = manifest;
    invalid.ExpiresAtUnixSeconds = invalid.IssuedAtUnixSeconds +
        OAC_MANIFEST_MAX_VALIDITY_SECONDS + 1;
    log.Expect("manifest bounded lifetime", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_TIME);
    invalid = manifest;
    invalid.ExpiresAtUnixSeconds = now;
    log.Expect("manifest expiration", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_EXPIRED);

    invalid = manifest;
    ++invalid.RequiredDriverProtocol;
    log.Expect("manifest driver compatibility", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INCOMPATIBLE_COMPONENT);
    invalid = manifest;
    ++invalid.RequiredServiceProtocol;
    log.Expect("manifest service compatibility", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INCOMPATIBLE_COMPONENT);
    invalid = manifest;
    ++invalid.RequiredLauncherProtocol;
    log.Expect("manifest launcher compatibility", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INCOMPATIBLE_COMPONENT);

    invalid = manifest;
    invalid.ExecutableName[2] = u'\\';
    log.Expect("manifest executable leaf", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_EXECUTABLE_NAME);
    invalid = manifest;
    invalid.ExecutableName[invalid.ExecutableNameLength] = u'X';
    log.Expect("manifest executable zero tail", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_EXECUTABLE_NAME);
    invalid = manifest;
    invalid.ExecutableName[0] = 0xD83D;
    invalid.ExecutableName[1] = u'X';
    log.Expect("manifest executable Unicode", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_EXECUTABLE_NAME);
    invalid = manifest;
    invalid.ExecutableName[invalid.ExecutableNameLength - 1] = u' ';
    log.Expect("manifest executable trailing alias", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_EXECUTABLE_NAME);

    invalid = manifest;
    invalid.ExecutableSize = 0;
    log.Expect("manifest nonzero executable size", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_FILE_IDENTITY);
    invalid = manifest;
    std::fill(
        std::begin(invalid.SigningKeyId),
        std::end(invalid.SigningKeyId),
        uint8_t{0});
    log.Expect("manifest nonzero signing key", OacManifestValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_MANIFEST_INVALID_FILE_IDENTITY);

    constexpr char16_t differentCaseName[] = u"game.EXE";
    log.Expect("manifest exact file identity",
        OacManifestFileIdentityMatches(
            &manifest,
            reinterpret_cast<const uint16_t*>(differentCaseName),
            std::size(differentCaseName) - 1,
            manifest.ExecutableSize,
            manifest.ExecutableSha256,
            manifest.SigningKeyId) != 0);
    auto wrongHash = std::array<uint8_t, OAC_MANIFEST_HASH_SIZE>{};
    log.Expect("manifest rejects wrong executable hash",
        OacManifestFileIdentityMatches(
            &manifest,
            manifest.ExecutableName,
            manifest.ExecutableNameLength,
            manifest.ExecutableSize,
            wrongHash.data(),
            manifest.SigningKeyId) == 0);
    log.Expect("manifest rejects wrong executable name",
        OacManifestFileIdentityMatches(
            &manifest,
            reinterpret_cast<const uint16_t*>(u"Other.exe"),
            9,
            manifest.ExecutableSize,
            manifest.ExecutableSha256,
            manifest.SigningKeyId) == 0);
    log.Expect("manifest rejects wrong executable size",
        OacManifestFileIdentityMatches(
            &manifest,
            manifest.ExecutableName,
            manifest.ExecutableNameLength,
            manifest.ExecutableSize + 1,
            manifest.ExecutableSha256,
            manifest.SigningKeyId) == 0);
    auto wrongSigner = std::array<uint8_t, OAC_MANIFEST_HASH_SIZE>{};
    std::copy(
        std::begin(manifest.SigningKeyId),
        std::end(manifest.SigningKeyId),
        wrongSigner.begin());
    wrongSigner[0] ^= 1;
    log.Expect("manifest rejects wrong executable signer",
        OacManifestFileIdentityMatches(
            &manifest,
            manifest.ExecutableName,
            manifest.ExecutableNameLength,
            manifest.ExecutableSize,
            manifest.ExecutableSha256,
            wrongSigner.data()) == 0);

    std::array<uint8_t, OAC_MANIFEST_HASH_SIZE> digest{};
    std::fill(digest.begin(), digest.end(), uint8_t{0xA5});
    OAC_MANIFEST_ROLLBACK_STATE state{};
    log.Expect("manifest first high-water state",
        OacManifestEvaluateRollback(
            &manifest,
            digest.data(),
            nullptr,
            0,
            &state) == OAC_MANIFEST_ROLLBACK_ACCEPT_NEW &&
        OacManifestRollbackStateValid(&state) != 0 &&
        state.Sequence == manifest.Sequence);
    OAC_MANIFEST_ROLLBACK_STATE next{};
    log.Expect("manifest current high-water state",
        OacManifestEvaluateRollback(
            &manifest,
            digest.data(),
            &state,
            1,
            &next) == OAC_MANIFEST_ROLLBACK_ACCEPT_CURRENT &&
        std::memcmp(&next, &state, sizeof(state)) == 0);
    invalid = manifest;
    --invalid.Sequence;
    log.Expect("manifest rollback rejected",
        OacManifestEvaluateRollback(
            &invalid,
            digest.data(),
            &state,
            1,
            &next) == OAC_MANIFEST_ROLLBACK_REJECT_OLDER);
    auto otherDigest = digest;
    otherDigest[0] ^= 1;
    log.Expect("manifest sequence equivocation rejected",
        OacManifestEvaluateRollback(
            &manifest,
            otherDigest.data(),
            &state,
            1,
            &next) == OAC_MANIFEST_ROLLBACK_REJECT_EQUIVOCATION);
    invalid = manifest;
    ++invalid.Sequence;
    invalid.BuildId[0] ^= 1;
    log.Expect("manifest monotonic update",
        OacManifestEvaluateRollback(
            &invalid,
            otherDigest.data(),
            &state,
            1,
            &next) == OAC_MANIFEST_ROLLBACK_ACCEPT_NEW &&
        next.Sequence == invalid.Sequence &&
        std::memcmp(
            next.ManifestSha256,
            otherDigest.data(),
            otherDigest.size()) == 0);
    auto corruptState = state;
    corruptState.Reserved[0] = 1;
    log.Expect("manifest corrupt high-water state",
        OacManifestEvaluateRollback(
            &manifest,
            digest.data(),
            &corruptState,
            1,
            &next) == OAC_MANIFEST_ROLLBACK_INVALID_STATE);
}

OAC_SIGNED_POLICY ValidSignedPolicy()
{
    OAC_SIGNED_POLICY policy{};
    constexpr std::array<uint8_t, 8> magic{
        'O', 'A', 'C', 'P', 'O', 'L', 'C', 'Y'
    };
    std::copy(magic.begin(), magic.end(), policy.Magic);
    policy.SchemaVersion = OAC_SIGNED_POLICY_SCHEMA;
    policy.Size = sizeof(policy);
    policy.Mode = OAC_POLICY_MODE_ENFORCE;
    for (size_t index = 0; index != OAC_POLICY_ID_SIZE; ++index)
    {
        policy.PolicyId[index] = static_cast<uint8_t>(index + 1);
        policy.GameId[index] = static_cast<uint8_t>(index + 17);
        policy.BuildId[index] = static_cast<uint8_t>(index + 33);
        policy.ChannelId[index] = static_cast<uint8_t>(index + 49);
    }
    policy.PolicyVersion = 7;
    policy.UpdateSequence = 10;
    policy.IssuedAtUnixSeconds = 999900;
    policy.ExpiresAtUnixSeconds = 1086400;
    policy.RequiredDriverProtocol = OAC_V5_VERSION;
    policy.RequiredServiceProtocol = OAC_IPC_PROTOCOL_REVISION;
    policy.RequiredLauncherProtocol = OAC_IPC_PROTOCOL_REVISION;
    policy.RuleCatalogRevision = OAC_POLICY_RULE_CATALOG_REVISION;
    policy.RuleCount = OAC_POLICY_RULE_COUNT;
    for (size_t index = 0; index != OAC_POLICY_HASH_SIZE; ++index)
        policy.SigningKeyId[index] = static_cast<uint8_t>(index + 65);
    size_t ruleCount = 0;
    const OAC_POLICY_RULE* rules = OacPolicyRuleCatalog(&ruleCount);
    if (rules != nullptr && ruleCount == OAC_POLICY_RULE_COUNT)
    {
        std::copy(rules, rules + ruleCount, policy.Rules);
    }
    policy.BackendLeaseMilliseconds = 6000;
    policy.BackendGraceMilliseconds = 2000;
    policy.BackendRenewalMilliseconds = 1000;
    policy.EvidenceAckTimeoutMilliseconds = 5000;
    return policy;
}

void TestSignedPolicy(TestLog& log)
{
    constexpr uint64_t now = 1000000;
    auto policy = ValidSignedPolicy();
    const auto validate = [&policy](uint64_t currentTime) {
        return OacSignedPolicyValidate(
            &policy,
            sizeof(policy),
            currentTime,
            OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION,
            OAC_IPC_PROTOCOL_REVISION);
    };

    log.Expect("valid canonical signed policy",
        validate(now) == OAC_SIGNED_POLICY_VALID);
    log.Expect("signed policy exact scope",
        OacSignedPolicyScopeMatches(
            &policy, policy.GameId, policy.BuildId) != 0);
    auto wrongBuild = std::array<uint8_t, OAC_POLICY_ID_SIZE>{};
    std::copy(
        std::begin(policy.BuildId), std::end(policy.BuildId), wrongBuild.begin());
    wrongBuild[0] ^= 1;
    log.Expect("signed policy rejects wrong scope",
        OacSignedPolicyScopeMatches(
            &policy, policy.GameId, wrongBuild.data()) == 0);
    log.Expect("signed policy null pointer",
        OacSignedPolicyValidate(
            nullptr, sizeof(policy), now, OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_POINTER);
    log.Expect("signed policy exact length",
        OacSignedPolicyValidate(
            &policy, sizeof(policy) - 1, now, OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_LENGTH);

    auto invalid = policy;
    invalid.Magic[0] ^= 1;
    log.Expect("signed policy magic", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_MAGIC);
    invalid = policy;
    ++invalid.SchemaVersion;
    log.Expect("signed policy schema", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_SCHEMA);
    invalid = policy;
    invalid.Reserved[0] = 1;
    log.Expect("signed policy reserved tail", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_RESERVED);
    invalid = policy;
    std::fill(
        std::begin(invalid.PolicyId),
        std::end(invalid.PolicyId),
        uint8_t{0});
    log.Expect("signed policy identity", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_IDENTITY);
    invalid = policy;
    invalid.IssuedAtUnixSeconds = now + OAC_POLICY_CLOCK_SKEW_SECONDS + 1;
    log.Expect("signed policy future issuance", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_TIME);
    invalid = policy;
    invalid.ExpiresAtUnixSeconds = now - OAC_POLICY_CLOCK_SKEW_SECONDS - 1;
    invalid.IssuedAtUnixSeconds = invalid.ExpiresAtUnixSeconds - 10;
    log.Expect("signed policy expiration", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_EXPIRED);
    invalid = policy;
    ++invalid.RequiredDriverProtocol;
    log.Expect("signed policy component compatibility", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INCOMPATIBLE_COMPONENT);
    invalid = policy;
    std::swap(invalid.Rules[0], invalid.Rules[1]);
    log.Expect("signed policy ordered rule identities", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_RULES);
    invalid = policy;
    invalid.Rules[0].EnforceAction =
        OAC_POLICY_ACTION_REQUEST_SERVER_REVIEW + 1;
    log.Expect("signed policy action range", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
             OAC_SIGNED_POLICY_INVALID_RULES);

    invalid = policy;
    invalid.BackendLeaseMilliseconds =
        OAC_BACKEND_MIN_LEASE_MILLISECONDS - 1;
    log.Expect("signed policy backend lease bound", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_OPERATION);
    invalid = policy;
    invalid.BackendGraceMilliseconds =
        OAC_BACKEND_MAX_GRACE_MILLISECONDS + 1;
    log.Expect("signed policy backend grace bound", OacSignedPolicyValidate(
        &invalid, sizeof(invalid), now, OAC_V5_VERSION,
        OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_OPERATION);
    invalid = policy;
    invalid.BackendRenewalMilliseconds = invalid.BackendLeaseMilliseconds;
    log.Expect("signed policy backend renewal ordering",
        OacSignedPolicyValidate(
            &invalid, sizeof(invalid), now, OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
                OAC_SIGNED_POLICY_INVALID_OPERATION);
    invalid = policy;
    invalid.EvidenceAckTimeoutMilliseconds =
        OAC_BACKEND_MIN_ACK_TIMEOUT_MILLISECONDS - 1;
    log.Expect("signed policy evidence acknowledgement bound",
        OacSignedPolicyValidate(
            &invalid, sizeof(invalid), now, OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
                OAC_SIGNED_POLICY_INVALID_OPERATION);

    invalid = policy;
    invalid.Flags = OAC_SIGNED_POLICY_EMERGENCY_REVOKE;
    invalid.EmergencyReason = OAC_POLICY_EMERGENCY_BUILD_WITHDRAWN;
    log.Expect("signed emergency revoke",
        OacSignedPolicyValidate(
            &invalid, sizeof(invalid), now, OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_VALID);
    invalid.Flags |= OAC_SIGNED_POLICY_ROLLBACK_AUTHORIZATION;
    invalid.RollbackFromPolicyVersion = policy.PolicyVersion + 1;
    std::fill(
        std::begin(invalid.RollbackFromPolicySha256),
        std::end(invalid.RollbackFromPolicySha256),
        uint8_t{0x31});
    log.Expect("signed policy rejects combined emergency rollback",
        OacSignedPolicyValidate(
            &invalid, sizeof(invalid), now, OAC_V5_VERSION,
            OAC_IPC_PROTOCOL_REVISION, OAC_IPC_PROTOCOL_REVISION) ==
            OAC_SIGNED_POLICY_INVALID_OPERATION);

    auto customized = policy;
    customized.Rules[1].EnforceAction = OAC_POLICY_ACTION_WARN;
    auto observation = ValidEventRecord();
    observation.RuleId = OAC_V5_RULE_SESSION_LOST;
    observation.EventType = OAC_V5_EVENT_REVOCATION;
    observation.Category = OAC_V5_CATEGORY_SERVICE;
    observation.ObservationSeverity = OAC_V5_OBSERVATION_CRITICAL;
    observation.EvidenceFlags = OAC_V5_EVIDENCE_KERNEL_SOURCE;
    OAC_POLICY_DECISION decision{};
    log.Expect("signed rules drive policy evaluation",
        OacPolicyEvaluateRules(
            customized.Mode,
            customized.Rules,
            customized.RuleCount,
            &observation,
            nullptr,
            &decision) != 0 &&
        decision.Action == OAC_POLICY_ACTION_WARN);

    std::array<uint8_t, OAC_POLICY_HASH_SIZE> firstDigest{};
    std::fill(firstDigest.begin(), firstDigest.end(), uint8_t{0xA1});
    OAC_POLICY_CACHE_STATE first{};
    log.Expect("signed policy first cache state",
        OacPolicyEvaluateUpdate(
            &policy, firstDigest.data(), nullptr, 0, &first) ==
            OAC_POLICY_UPDATE_ACCEPT_NEW &&
        OacPolicyCacheStateValid(&first) != 0 &&
        first.HighestPolicyVersion == policy.PolicyVersion);
    OAC_POLICY_CACHE_STATE next{};
    log.Expect("signed policy current cache state",
        OacPolicyEvaluateUpdate(
            &policy, firstDigest.data(), &first, 1, &next) ==
            OAC_POLICY_UPDATE_ACCEPT_CURRENT &&
        std::memcmp(&next, &first, sizeof(next)) == 0);
    auto otherDigest = firstDigest;
    otherDigest[0] ^= 1;
    log.Expect("signed policy sequence equivocation",
        OacPolicyEvaluateUpdate(
            &policy, otherDigest.data(), &first, 1, &next) ==
            OAC_POLICY_UPDATE_REJECT_EQUIVOCATION);

    auto newer = policy;
    ++newer.PolicyVersion;
    ++newer.UpdateSequence;
    std::array<uint8_t, OAC_POLICY_HASH_SIZE> newerDigest{};
    std::fill(newerDigest.begin(), newerDigest.end(), uint8_t{0xB2});
    OAC_POLICY_CACHE_STATE highWater{};
    log.Expect("signed policy monotonic update",
        OacPolicyEvaluateUpdate(
            &newer, newerDigest.data(), &first, 1, &highWater) ==
            OAC_POLICY_UPDATE_ACCEPT_NEW &&
        highWater.HighestPolicyVersion == newer.PolicyVersion &&
        highWater.CurrentPolicyVersion == newer.PolicyVersion);

    auto rollback = policy;
    rollback.UpdateSequence = newer.UpdateSequence + 1;
    rollback.Flags = OAC_SIGNED_POLICY_ROLLBACK_AUTHORIZATION;
    rollback.RollbackFromPolicyVersion = newer.PolicyVersion;
    std::copy(
        newerDigest.begin(), newerDigest.end(),
        rollback.RollbackFromPolicySha256);
    std::array<uint8_t, OAC_POLICY_HASH_SIZE> rollbackDigest{};
    std::fill(rollbackDigest.begin(), rollbackDigest.end(), uint8_t{0xC3});
    OAC_POLICY_CACHE_STATE rolledBack{};
    log.Expect("signed explicit rollback",
        OacPolicyEvaluateUpdate(
            &rollback,
            rollbackDigest.data(),
            &highWater,
            1,
            &rolledBack) == OAC_POLICY_UPDATE_ACCEPT_ROLLBACK &&
        rolledBack.HighestPolicyVersion == newer.PolicyVersion &&
        rolledBack.CurrentPolicyVersion == rollback.PolicyVersion);
    auto replay = newer;
    replay.UpdateSequence = rollback.UpdateSequence + 1;
    log.Expect("signed rollback preserves historical high water",
        OacPolicyEvaluateUpdate(
            &replay,
            newerDigest.data(),
            &rolledBack,
            1,
            &next) == OAC_POLICY_UPDATE_REJECT_REPLAY);
    rollback.RollbackFromPolicySha256[0] ^= 1;
    log.Expect("signed rollback binds current digest",
        OacPolicyEvaluateUpdate(
            &rollback,
            rollbackDigest.data(),
            &highWater,
            1,
            &next) == OAC_POLICY_UPDATE_REJECT_ROLLBACK);

    auto corrupt = first;
    corrupt.Reserved[0] = 1;
    log.Expect("signed policy rejects corrupt cache",
        OacPolicyEvaluateUpdate(
            &newer,
            newerDigest.data(),
            &corrupt,
            1,
            &next) == OAC_POLICY_UPDATE_INVALID_STATE);
}

OAC_BACKEND_EVIDENCE_ITEM ValidBackendEvidenceItem(
    const OAC_SIGNED_POLICY& policy,
    uint64_t serviceSequence)
{
    OAC_BACKEND_EVIDENCE_ITEM item{};
    item.Record = ValidEventRecord();
    item.Record.ObservationSeverity = OAC_V5_OBSERVATION_CRITICAL;
    item.Record.EvidenceFlags |= OAC_V5_EVIDENCE_CALLBACK_SOURCE;
    item.Record.IngestionTimestamp100ns = item.Record.Timestamp100ns;
    item.Record.ServiceSequence = serviceSequence;
    if (!OacPolicyEvaluateRules(
            policy.Mode,
            policy.Rules,
            policy.RuleCount,
            &item.Record,
            nullptr,
            &item.Decision) ||
        !OacPolicyApplyDecision(&item.Record, &item.Decision))
    {
        item = {};
        return item;
    }
    item.SourceChannel = OAC_EVIDENCE_CHANNEL_ALERT;
    return item;
}

void InitializeBackendRequestHeader(
    OAC_BACKEND_REQUEST_HEADER& header,
    uint32_t size,
    uint32_t messageType,
    uint64_t sequence,
    uint64_t now,
    bool sessionRequired)
{
    header = {};
    header.Revision = OAC_BACKEND_PROTOCOL_REVISION;
    header.Size = size;
    header.MessageType = messageType;
    header.RequestSequence = sequence;
    std::fill(
        std::begin(header.Nonce), std::end(header.Nonce), uint8_t{0x31});
    if (sessionRequired)
    {
        std::fill(
            std::begin(header.SessionId),
            std::end(header.SessionId),
            uint8_t{0x42});
    }
    header.IssuedAtUnixSeconds = now;
    header.ExpiresAtUnixSeconds = now + 30;
}

OAC_BACKEND_OPEN_REQUEST ValidBackendOpenRequest(uint64_t now)
{
    OAC_BACKEND_OPEN_REQUEST request{};
    InitializeBackendRequestHeader(
        request.Header,
        sizeof(request),
        OAC_BACKEND_MESSAGE_OPEN_SESSION,
        1,
        now,
        false);
    std::fill(std::begin(request.GameId), std::end(request.GameId), uint8_t{1});
    std::fill(std::begin(request.BuildId), std::end(request.BuildId), uint8_t{2});
    std::fill(
        std::begin(request.PolicyId), std::end(request.PolicyId), uint8_t{3});
    std::fill(
        std::begin(request.PolicySha256),
        std::end(request.PolicySha256),
        uint8_t{4});
    request.MaximumLeaseMilliseconds = 4000;
    request.MaximumGraceMilliseconds = 2000;
    request.RenewalIntervalMilliseconds = 1000;
    request.EvidenceAckTimeoutMilliseconds = 2000;
    return request;
}

void InitializeBackendResponseHeader(
    OAC_BACKEND_RESPONSE_HEADER& header,
    uint32_t size,
    uint32_t messageType,
    const OAC_BACKEND_REQUEST_HEADER& request,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE])
{
    header = {};
    header.Revision = OAC_BACKEND_PROTOCOL_REVISION;
    header.Size = size;
    header.MessageType = messageType;
    header.RequestSequence = request.RequestSequence;
    header.Result = OAC_BACKEND_RESULT_ACCEPTED;
    std::fill(
        std::begin(header.SessionId),
        std::end(header.SessionId),
        uint8_t{0x42});
    std::copy(
        requestNonceSha256,
        requestNonceSha256 + OAC_BACKEND_DIGEST_SIZE,
        header.RequestNonceSha256);
}

OAC_BACKEND_OPEN_RESPONSE ValidBackendOpenResponse(
    const OAC_BACKEND_OPEN_REQUEST& request,
    const uint8_t requestNonceSha256[OAC_BACKEND_DIGEST_SIZE])
{
    OAC_BACKEND_OPEN_RESPONSE response{};
    InitializeBackendResponseHeader(
        response.Header,
        sizeof(response),
        OAC_BACKEND_MESSAGE_OPEN_SESSION,
        request.Header,
        requestNonceSha256);
    std::fill(
        std::begin(response.ServerNonce),
        std::end(response.ServerNonce),
        uint8_t{0x53});
    response.LeaseSequence = 1;
    response.LeaseMilliseconds = request.MaximumLeaseMilliseconds;
    response.GraceMilliseconds = request.MaximumGraceMilliseconds;
    response.RenewalIntervalMilliseconds =
        request.RenewalIntervalMilliseconds;
    return response;
}

void TestBackendRecords(TestLog& log, const OAC_SIGNED_POLICY& policy)
{
    constexpr uint64_t now = 1000000;
    auto open = ValidBackendOpenRequest(now);
    log.Expect("backend open request accepts canonical fields",
        OacBackendValidateOpenRequest(&open, sizeof(open), now) != 0);
    auto invalidOpen = open;
    invalidOpen.Header.Flags = 1;
    log.Expect("backend open request rejects flags",
        OacBackendValidateOpenRequest(
            &invalidOpen, sizeof(invalidOpen), now) == 0);
    invalidOpen = open;
    invalidOpen.Header.SessionId[0] = 1;
    log.Expect("backend open request rejects an existing session",
        OacBackendValidateOpenRequest(
            &invalidOpen, sizeof(invalidOpen), now) == 0);
    invalidOpen = open;
    invalidOpen.Header.IssuedAtUnixSeconds =
        now + OAC_BACKEND_CLOCK_SKEW_SECONDS + 1;
    invalidOpen.Header.ExpiresAtUnixSeconds =
        invalidOpen.Header.IssuedAtUnixSeconds + 1;
    log.Expect("backend open request rejects excessive clock skew",
        OacBackendValidateOpenRequest(
            &invalidOpen, sizeof(invalidOpen), now) == 0);
    invalidOpen = open;
    invalidOpen.Header.ExpiresAtUnixSeconds =
        invalidOpen.Header.IssuedAtUnixSeconds;
    log.Expect("backend open request requires a nonempty lifetime",
        OacBackendValidateOpenRequest(
            &invalidOpen, sizeof(invalidOpen), now) == 0);
    log.Expect("backend open request requires a current clock",
        OacBackendValidateOpenRequest(&open, sizeof(open), 0) == 0);
    invalidOpen = open;
    std::fill(
        std::begin(invalidOpen.PolicySha256),
        std::end(invalidOpen.PolicySha256),
        uint8_t{});
    log.Expect("backend open request requires policy identity",
        OacBackendValidateOpenRequest(
            &invalidOpen, sizeof(invalidOpen), now) == 0);

    auto edgeTime = ValidBackendOpenRequest(UINT64_MAX - 10);
    edgeTime.Header.IssuedAtUnixSeconds = UINT64_MAX - 5;
    edgeTime.Header.ExpiresAtUnixSeconds = UINT64_MAX;
    log.Expect("backend request time check is overflow safe",
        OacBackendValidateOpenRequest(
            &edgeTime, sizeof(edgeTime), UINT64_MAX - 10) != 0);

    std::array<uint8_t, OAC_BACKEND_DIGEST_SIZE> requestDigest{};
    requestDigest.fill(0x61);
    auto openResponse = ValidBackendOpenResponse(open, requestDigest.data());
    log.Expect("backend open response accepts exact correlation",
        OacBackendValidateOpenResponse(
            &open,
            &openResponse,
            sizeof(openResponse),
            requestDigest.data()) != 0);
    auto invalidOpenResponse = openResponse;
    invalidOpenResponse.Header.SessionId[0] = 0;
    std::fill(
        std::begin(invalidOpenResponse.Header.SessionId),
        std::end(invalidOpenResponse.Header.SessionId),
        uint8_t{});
    log.Expect("backend open response requires a session identity",
        OacBackendValidateOpenResponse(
            &open,
            &invalidOpenResponse,
            sizeof(invalidOpenResponse),
            requestDigest.data()) == 0);
    invalidOpenResponse = openResponse;
    invalidOpenResponse.EvidenceAcknowledgedThrough = 1;
    log.Expect("backend open response cannot pre-acknowledge evidence",
        OacBackendValidateOpenResponse(
            &open,
            &invalidOpenResponse,
            sizeof(invalidOpenResponse),
            requestDigest.data()) == 0);
    invalidOpenResponse = openResponse;
    invalidOpenResponse.RenewalIntervalMilliseconds /= 2;
    log.Expect("backend open response cannot rewrite renewal policy",
        OacBackendValidateOpenResponse(
            &open,
            &invalidOpenResponse,
            sizeof(invalidOpenResponse),
            requestDigest.data()) == 0);

    OAC_BACKEND_RENEW_REQUEST renewal{};
    InitializeBackendRequestHeader(
        renewal.Header,
        sizeof(renewal),
        OAC_BACKEND_MESSAGE_RENEW_LEASE,
        2,
        now,
        true);
    renewal.CurrentLeaseSequence = 1;
    log.Expect("backend renewal request accepts canonical fields",
        OacBackendValidateRenewRequest(
            &renewal, sizeof(renewal), now) != 0);
    OAC_BACKEND_RENEW_RESPONSE renewed{};
    InitializeBackendResponseHeader(
        renewed.Header,
        sizeof(renewed),
        OAC_BACKEND_MESSAGE_RENEW_LEASE,
        renewal.Header,
        requestDigest.data());
    renewed.LeaseSequence = 2;
    renewed.LeaseMilliseconds = 4000;
    renewed.GraceMilliseconds = 2000;
    renewed.RenewalIntervalMilliseconds = 1000;
    log.Expect("backend renewal response advances the lease",
        OacBackendValidateRenewResponse(
            &renewal,
            &renewed,
            sizeof(renewed),
            requestDigest.data(),
            4000,
            2000,
            1000) != 0);
    auto invalidRenewed = renewed;
    invalidRenewed.LeaseSequence = renewal.CurrentLeaseSequence;
    log.Expect("backend renewal response rejects replayed leases",
        OacBackendValidateRenewResponse(
            &renewal,
            &invalidRenewed,
            sizeof(invalidRenewed),
            requestDigest.data(),
            4000,
            2000,
            1000) == 0);
    invalidRenewed = renewed;
    invalidRenewed.RenewalIntervalMilliseconds /= 2;
    log.Expect("backend renewal cannot rewrite renewal policy",
        OacBackendValidateRenewResponse(
            &renewal,
            &invalidRenewed,
            sizeof(invalidRenewed),
            requestDigest.data(),
            4000,
            2000,
            1000) == 0);

    const auto item = ValidBackendEvidenceItem(policy, 1);
    OAC_BACKEND_EVIDENCE_METADATA metadata{};
    InitializeBackendRequestHeader(
        metadata.Header,
        sizeof(metadata),
        OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE,
        3,
        now,
        true);
    std::array<uint8_t, OAC_BACKEND_DIGEST_SIZE> binding{};
    binding.fill(0x71);
    std::copy(binding.begin(), binding.end(), metadata.BindingSha256);
    metadata.FirstServiceSequence = 1;
    metadata.LastServiceSequence = 1;
    metadata.RecordCount = 1;
    log.Expect("backend evidence batch accepts canonical records",
        OacBackendValidateEvidenceBatch(
            &metadata,
            sizeof(metadata),
            &item,
            1,
            now,
            binding.data()) != 0);
    auto invalidMetadata = metadata;
    invalidMetadata.LastServiceSequence = 2;
    log.Expect("backend evidence batch rejects sequence gaps",
        OacBackendValidateEvidenceBatch(
            &invalidMetadata,
            sizeof(invalidMetadata),
            &item,
            1,
            now,
            binding.data()) == 0);
    invalidMetadata = metadata;
    invalidMetadata.FirstServiceSequence = UINT64_MAX;
    invalidMetadata.LastServiceSequence = UINT64_MAX;
    invalidMetadata.RecordCount = 2;
    std::array<OAC_BACKEND_EVIDENCE_ITEM, 2> overflowItems{item, item};
    log.Expect("backend evidence sequence range is overflow safe",
        OacBackendValidateEvidenceBatch(
            &invalidMetadata,
            sizeof(invalidMetadata),
            overflowItems.data(),
            overflowItems.size(),
            now,
            binding.data()) == 0);
    auto invalidItem = item;
    invalidItem.Decision.RuleId ^= 1;
    log.Expect("backend evidence binds the policy decision",
        OacBackendValidateEvidenceBatch(
            &metadata,
            sizeof(metadata),
            &invalidItem,
            1,
            now,
            binding.data()) == 0);

    OAC_BACKEND_UPLOAD_RESPONSE upload{};
    InitializeBackendResponseHeader(
        upload.Header,
        sizeof(upload),
        OAC_BACKEND_MESSAGE_UPLOAD_EVIDENCE,
        metadata.Header,
        requestDigest.data());
    upload.AcknowledgedThrough = 1;
    log.Expect("backend upload response acknowledges delivered evidence",
        OacBackendValidateUploadResponse(
            &metadata,
            &upload,
            sizeof(upload),
            requestDigest.data(),
            0) != 0);
    upload.AcknowledgedThrough = 2;
    log.Expect("backend upload response rejects undelivered acknowledgement",
        OacBackendValidateUploadResponse(
            &metadata,
            &upload,
            sizeof(upload),
            requestDigest.data(),
            0) == 0);
}

void TestBackendSession(TestLog& log)
{
    log.Expect("backend policy accepts bounded intervals",
        OacBackendPolicyValid(4000, 2000, 1000, 2000) != 0);
    log.Expect("backend policy rejects renewal at lease boundary",
        OacBackendPolicyValid(4000, 2000, 4000, 2000) == 0);
    log.Expect("backend policy rejects short acknowledgement timeout",
        OacBackendPolicyValid(4000, 2000, 1000, 999) == 0);

    std::array<uint8_t, OAC_BACKEND_DIGEST_SIZE> nonceDigest{};
    nonceDigest[0] = 1;
    OAC_BACKEND_REPLAY_WINDOW replayWindow{};
    log.Expect("backend accepts a fresh nonce digest",
        OacBackendAcceptNonceDigest(
            &replayWindow, nonceDigest.data()) != 0);
    log.Expect("backend rejects a replayed nonce digest",
        OacBackendAcceptNonceDigest(
            &replayWindow, nonceDigest.data()) == 0);
    bool filledWindow = true;
    for (uint8_t value = 2;
         value <= OAC_BACKEND_REPLAY_WINDOW_SIZE + 1;
         ++value)
    {
        auto candidate = nonceDigest;
        candidate[0] = value;
        filledWindow = filledWindow && OacBackendAcceptNonceDigest(
            &replayWindow, candidate.data()) != 0;
    }
    log.Expect("backend replay window remains bounded", filledWindow &&
        replayWindow.Count == OAC_BACKEND_REPLAY_WINDOW_SIZE &&
        OacBackendAcceptNonceDigest(
            &replayWindow, nonceDigest.data()) != 0);
    auto corruptWindow = replayWindow;
    corruptWindow.Next = OAC_BACKEND_REPLAY_WINDOW_SIZE;
    log.Expect("backend rejects corrupt replay state",
        OacBackendAcceptNonceDigest(
            &corruptWindow, nonceDigest.data()) == 0);
    OAC_BACKEND_REPLAY_WINDOW partialWindow{};
    partialWindow.Count = 1;
    log.Expect("backend rejects a corrupt partial replay window",
        OacBackendAcceptNonceDigest(
            &partialWindow, nonceDigest.data()) == 0);

    log.Expect("backend accepts a current acknowledgement",
        OacBackendEvaluateAcknowledgement(4, 7, 4) ==
            OAC_BACKEND_ACK_ACCEPT_CURRENT);
    log.Expect("backend accepts acknowledgement progress",
        OacBackendEvaluateAcknowledgement(4, 7, 7) ==
            OAC_BACKEND_ACK_ACCEPT_PROGRESS);
    log.Expect("backend rejects acknowledgement replay",
        OacBackendEvaluateAcknowledgement(4, 7, 3) ==
            OAC_BACKEND_ACK_REJECT_REPLAY);
    log.Expect("backend rejects acknowledgement beyond delivery",
        OacBackendEvaluateAcknowledgement(4, 7, 8) ==
            OAC_BACKEND_ACK_REJECT_UNDELIVERED);
    log.Expect("backend evidence starts clear",
        OacBackendEvaluateEvidenceState(100, 0, 2000, 0, 64, 0) ==
            OAC_BACKEND_EVIDENCE_CLEAR);
    log.Expect("backend evidence remains pending before its deadline",
        OacBackendEvaluateEvidenceState(2099, 100, 2000, 1, 64, 0) ==
            OAC_BACKEND_EVIDENCE_PENDING);
    log.Expect("backend evidence acknowledgement timeout is explicit",
        OacBackendEvaluateEvidenceState(2100, 100, 2000, 1, 64, 0) ==
            OAC_BACKEND_EVIDENCE_ACK_TIMEOUT);
    log.Expect("backend evidence queue exhaustion is explicit",
        OacBackendEvaluateEvidenceState(200, 100, 2000, 64, 64, 1) ==
            OAC_BACKEND_EVIDENCE_QUEUE_FULL);

    oac::VerifiedPolicy policy{};
    policy.Record = ValidSignedPolicy();
    std::fill(policy.Digest.begin(), policy.Digest.end(), uint8_t{0xD5});
    TestBackendRecords(log, policy.Record);
    const auto evidence = ValidBackendEvidenceItem(policy.Record, 1);
    log.Expect("backend evidence fixture is canonical",
        OacV5ValidateEventRecord(
            &evidence.Record, sizeof(evidence.Record)) == OAC_V5_VALID &&
        evidence.Decision.RuleId == evidence.Record.RuleId);

    const ULONGLONG now = GetTickCount64();
    auto normal = std::make_unique<oac::BackendSession>();
    DWORD error = normal->Start(
        policy,
        std::make_unique<oac::MockBackendTransport>(
            oac::BackendScenario::Normal));
    const auto initial = normal->Status();
    log.Expect("mock backend opens an authenticated lease",
        error == ERROR_SUCCESS && normal->AllowsLaunch(now) &&
        initial.Authenticated && initial.TestDouble &&
        initial.LeaseState == OAC_LEASE_HEALTHY &&
        initial.LeaseSequence == 1 &&
        !std::all_of(
            normal->BindingSha256().begin(),
            normal->BindingSha256().end(),
            [](uint8_t value) { return value == 0; }));
    log.Expect("launch authorization checks the current lease deadline",
        !normal->AllowsLaunch(
            now + policy.Record.BackendLeaseMilliseconds));
    error = normal->Enqueue(evidence, now);
    if (error == ERROR_SUCCESS) error = normal->Poll(now);
    const auto acknowledged = normal->Status();
    log.Expect("mock backend acknowledges delivered evidence",
        error == ERROR_SUCCESS && acknowledged.PendingEvidence == 0 &&
        acknowledged.AcknowledgedSequence == 1 &&
        acknowledged.AlertAcknowledgedSequence == evidence.Record.Sequence);
    normal->Stop();
    error = normal->Start(
        policy,
        std::make_unique<oac::MockBackendTransport>(
            oac::BackendScenario::Normal));
    if (error == ERROR_SUCCESS) error = normal->Enqueue(evidence, now);
    if (error == ERROR_SUCCESS) error = normal->Poll(now);
    log.Expect("backend session can restart from clean state",
        error == ERROR_SUCCESS && normal->Status().PendingEvidence == 0 &&
        normal->Status().AcknowledgedSequence == 1);

    auto replay = std::make_unique<oac::BackendSession>();
    error = replay->Start(
        policy,
        std::make_unique<oac::MockBackendTransport>(
            oac::BackendScenario::ReplayOpen));
    log.Expect("mock backend rejects a replayed open nonce",
        error == ERROR_RETRY && !replay->AllowsLaunch(now));

    auto missingAcknowledgement = std::make_unique<oac::BackendSession>();
    error = missingAcknowledgement->Start(
        policy,
        std::make_unique<oac::MockBackendTransport>(
            oac::BackendScenario::HoldAcknowledgement));
    if (error == ERROR_SUCCESS)
        error = missingAcknowledgement->Enqueue(evidence, now);
    if (error == ERROR_SUCCESS) error = missingAcknowledgement->Poll(now);
    if (error == ERROR_SUCCESS)
    {
        error = missingAcknowledgement->Poll(
            now + policy.Record.EvidenceAckTimeoutMilliseconds);
    }
    log.Expect("unacknowledged evidence terminates the backend session",
        error == ERROR_TIMEOUT && !missingAcknowledgement->AllowsLaunch(now) &&
        missingAcknowledgement->Status().PendingEvidence == 1);

    auto lostLease = std::make_unique<oac::BackendSession>();
    error = lostLease->Start(
        policy,
        std::make_unique<oac::MockBackendTransport>(
            oac::BackendScenario::StopRenewing));
    if (error == ERROR_SUCCESS)
    {
        error = lostLease->Poll(
            now + policy.Record.BackendRenewalMilliseconds);
    }
    if (error == ERROR_SUCCESS)
    {
        error = lostLease->Poll(
            now + policy.Record.BackendLeaseMilliseconds +
            policy.Record.BackendGraceMilliseconds);
    }
    log.Expect("lease loss terminates the backend session",
        error == ERROR_TIMEOUT && !lostLease->AllowsLaunch(now) &&
        lostLease->Status().LeaseState == OAC_LEASE_EXPIRED);

    auto revokedLease = std::make_unique<oac::BackendSession>();
    error = revokedLease->Start(
        policy,
        std::make_unique<oac::MockBackendTransport>(
            oac::BackendScenario::RevokeLease));
    if (error == ERROR_SUCCESS)
    {
        error = revokedLease->Poll(
            now + policy.Record.BackendRenewalMilliseconds);
    }
    log.Expect("backend revocation terminates the session",
        error == ERROR_ACCESS_DISABLED_BY_POLICY &&
        !revokedLease->AllowsLaunch(now) &&
        revokedLease->Status().LeaseState == OAC_LEASE_REVOKED);
}
} // namespace

int main()
{
    TestLog log;
    TestCodes(log);
    TestBasicHelpers(log);
    TestServiceFailures(log);
    TestServiceLaunchMessages(log);
    TestServiceScanMetrics(log);
    TestServiceBackendStatus(log);
    TestThreadSuspension(log);
    TestRanges(log);
    TestNegotiateRequest(log);
    TestClaimAndStatusRequests(log);
    TestRevokeMessages(log);
    TestLaunchRequests(log);
    TestLaunchResponses(log);
    TestResponses(log);
    TestCorrelationAndIds(log);
    TestSessionTransitions(log);
    TestLaunchDecision(log);
    TestLeasePolicy(log);
    TestEvidenceTransport(log);
    TestSnapshotTransport(log);
    TestLabEvidenceContract(log);
    TestEventRecords(log);
    TestPolicyCatalog(log);
    TestSignerClassification(log);
    TestPolicyEvaluation(log);
    TestGameManifest(log);
    TestSignedPolicy(log);
    TestBackendSession(log);
    return log.ExitCode();
}
