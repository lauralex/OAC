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
#include "../../shared/oac_ipc.h"
#include "../../shared/protocol/oac_v5.h"
#include "../../shared/protocol/oac_validate.h"

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
static_assert(sizeof(OAC_ARM_LAUNCH_REQUEST) == 2112);
static_assert(offsetof(OAC_ARM_LAUNCH_REQUEST, CanonicalNtPath) == 64);
static_assert(offsetof(OAC_ARM_LAUNCH_REQUEST,
    CanonicalDosDevicePath) == 1088);
static_assert(sizeof(OAC_ARM_LAUNCH_RESPONSE) == 88);
static_assert(sizeof(OAC_CANCEL_LAUNCH_REQUEST) == 64);
static_assert(sizeof(OAC_CANCEL_LAUNCH_RESPONSE) == 64);
static_assert(sizeof(OAC_CONFIRM_TARGET_REQUEST) == 72);
static_assert(sizeof(OAC_CONFIRM_TARGET_RESPONSE) == 72);
static_assert(std::is_standard_layout_v<OAC_IPC_LAUNCH_REQUEST>);
static_assert(sizeof(OAC_IPC_LAUNCH_REQUEST) == 1056);
static_assert(offsetof(OAC_IPC_LAUNCH_REQUEST, ExecutablePath) == 32);
static_assert(sizeof(OAC_IPC_LAUNCH_RESPONSE) == 56);

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
    response.MaximumEventCount = OAC_V5_MAX_EVENT_COUNT;
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

void TestCodes(TestLog& log)
{
    const std::array<DWORD, 17> codes =
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
        IOCTL_OAC_V5_READ_EVENTS,
        IOCTL_OAC_V5_CPU_SNAPSHOT,
        IOCTL_OAC_V5_GET_STATUS,
        IOCTL_OAC_V5_REVOKE_SESSION,
        IOCTL_OAC_ARM_LAUNCH,
        IOCTL_OAC_CANCEL_LAUNCH,
        IOCTL_OAC_CONFIRM_TARGET
    };
    const std::set<DWORD> unique(codes.begin(), codes.end());
    const std::array<OAC_V5_MESSAGE_TYPE, 11> messages =
    {
        OAC_V5_MESSAGE_NEGOTIATE,
        OAC_V5_MESSAGE_CLAIM_SESSION,
        OAC_V5_MESSAGE_SET_CONFIG,
        OAC_V5_MESSAGE_RUN_SCAN,
        OAC_V5_MESSAGE_READ_EVENTS,
        OAC_V5_MESSAGE_CPU_SNAPSHOT,
        OAC_V5_MESSAGE_GET_STATUS,
        OAC_V5_MESSAGE_REVOKE_SESSION,
        OAC_MESSAGE_ARM_LAUNCH,
        OAC_MESSAGE_CANCEL_LAUNCH,
        OAC_MESSAGE_CONFIRM_TARGET
    };
    bool buffered = true;
    bool restricted = true;
    bool messageMatch = true;
    for (std::size_t index = 6; index < codes.size(); ++index)
    {
        buffered = buffered && METHOD_FROM_CTL_CODE(codes[index]) == METHOD_BUFFERED;
        restricted = restricted &&
            ((codes[index] >> 14) & 3UL) == OAC_V5_IOCTL_ACCESS;
        messageMatch = messageMatch &&
            ((codes[index] >> 2) & 0xFFFUL) == messages[index - 6];
    }
    log.Expect("v4 and v5 IOCTLs are distinct", unique.size() == codes.size());
    log.Expect("v5 IOCTLs use buffered I/O", buffered);
    log.Expect("v5 IOCTLs require read and write access", restricted);
    log.Expect("v5 message IDs match IOCTL functions", messageMatch);
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
        OAC_PRODUCTION_PROTOCOL_VERSION == 0x00050002UL);
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

    uint32_t stage = 0;
    uint32_t error = 0;
    log.Expect("service failure decoding", OacDecodeServiceFailure(
        encoded, &stage, &error) != 0 &&
        stage == OAC_SERVICE_STAGE_DRIVER_OPEN &&
        error == ERROR_ACCESS_DENIED);
    log.Expect("service failure zero stage", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_NONE, ERROR_ACCESS_DENIED) == 0);
    log.Expect("service failure unknown stage", OacEncodeServiceFailure(
        OAC_SERVICE_STAGE_RUNTIME + 1, ERROR_ACCESS_DENIED) == 0);
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
         expectedStage <= OAC_SERVICE_STAGE_RUNTIME;
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
            (10u << OAC_SERVICE_FAILURE_STAGE_SHIFT) |
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
        OAC_IPC_LAUNCH_CONFIRMED | OAC_IPC_LAUNCH_RESUMED;
    response.ServiceProcessId = 10;
    response.ClientProcessId = 11;
    response.ClientSessionId = 1;
    response.TargetProcessId = 12;
    log.Expect("service launch success response", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) != 0);

    auto badResponse = response;
    badResponse.LaunchFlags = OAC_IPC_LAUNCH_CONFIRMED;
    log.Expect("service launch incomplete response", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    badResponse = response;
    badResponse.TargetProcessId = 0;
    log.Expect("service launch missing target", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    badResponse = response;
    badResponse.Reserved = 1;
    log.Expect("service launch response reserved", OacIpcValidateLaunchResponse(
        &badResponse, sizeof(badResponse), request.Header.RequestId) == 0);
    log.Expect("service launch response correlation", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId + 1) == 0);

    response = {};
    response.Header.Version = OAC_IPC_PROTOCOL_REVISION;
    response.Header.Size = sizeof(response);
    response.Header.Type = OAC_IPC_TYPE_LAUNCH_RESPONSE;
    response.Header.RequestId = request.Header.RequestId;
    response.Win32Error = ERROR_ACCESS_DENIED;
    log.Expect("service launch rejection response", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) != 0);
    response.TargetProcessId = 12;
    log.Expect("service launch rejection has no identity", OacIpcValidateLaunchResponse(
        &response, sizeof(response), request.Header.RequestId) == 0);
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
    log.Expect("valid diagnostic claim", OacV5ValidateClaimRequest(
        &claim, sizeof(claim)) == OAC_V5_VALID);
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
    status.Header.Flags = OAC_V5_RESPONSE_PARTIAL;
    log.Expect("status disallowed response flag", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_FLAGS);
    status = ValidStatusResponse();
    status.Header.MessageType = OAC_V5_MESSAGE_READ_EVENTS;
    log.Expect("status response wrong message type", OacV5ValidateStatusResponse(
        &status, sizeof(status)) == OAC_V5_INVALID_MESSAGE_TYPE);
    status = ValidStatusResponse();
    status.TargetProcessId = 200;
    log.Expect("claimed status rejects target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_LAUNCH_PENDING;
    status.TargetProcessId = 200;
    log.Expect("pending status rejects target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_TARGET_BOUND;
    log.Expect("bound status requires target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status.TargetProcessId = 200;
    log.Expect("bound status accepts target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_MONITORING;
    log.Expect("monitoring status requires target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_INVALID_VALUE);
    status.TargetProcessId = 200;
    log.Expect("monitoring status accepts target identity",
        OacV5ValidateStatusResponse(
            &status, sizeof(status)) == OAC_V5_VALID);
    status = ValidStatusResponse();
    status.State = OAC_V5_SESSION_REVOKED;
    status.RevokeReason = OAC_REVOKE_TARGET_CONFIRMATION_FAILED;
    status.Header.Flags = OAC_V5_RESPONSE_REVOKED;
    status.TargetProcessId = 200;
    log.Expect("terminal tombstone may retain target identity",
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
} // namespace

int main()
{
    TestLog log;
    TestCodes(log);
    TestBasicHelpers(log);
    TestServiceFailures(log);
    TestServiceLaunchMessages(log);
    TestRanges(log);
    TestNegotiateRequest(log);
    TestClaimAndStatusRequests(log);
    TestLaunchRequests(log);
    TestLaunchResponses(log);
    TestResponses(log);
    TestCorrelationAndIds(log);
    TestSessionTransitions(log);
    TestLaunchDecision(log);
    TestEventRecords(log);
    return log.ExitCode();
}
