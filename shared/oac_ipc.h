#pragma once

/*
 * Fixed local protocol between the unprivileged launcher and OACService.
 * The pipe is a trust boundary: keep every layout fixed-width and reject
 * messages whose version, size, type, flags, or reserved fields differ.
 */

#include <stddef.h>
#include <stdint.h>

#include "oac_lease.h"

#define OAC_IPC_PROTOCOL_REVISION 0x00010006u
#define OAC_IPC_VERSION OAC_IPC_PROTOCOL_REVISION
#define OAC_IPC_MAX_MESSAGE_SIZE 4096u
#define OAC_IPC_MAX_EXECUTABLE_PATH_CHARS 512u

#define OAC_SERVICE_NAME L"OACService"
#define OAC_SERVICE_ACCOUNT L"NT SERVICE\\OACService"
#define OAC_SERVICE_SID \
    L"S-1-5-80-1726785755-3364470821-2652420548-2779146334-590817200"
#define OAC_PIPE_NAME L"\\\\.\\pipe\\OAC.Control"

/* Read/write without FILE_APPEND_DATA, which is FILE_CREATE_PIPE_INSTANCE. */
#define OAC_PIPE_CLIENT_ACCESS 0x0012019Bu

#define OAC_IPC_TYPE_HELLO_REQUEST 0x00000001u
#define OAC_IPC_TYPE_STATUS_REQUEST 0x00000002u
#define OAC_IPC_TYPE_LAUNCH_REQUEST 0x00000003u
#define OAC_IPC_TYPE_HELLO_RESPONSE 0x80000001u
#define OAC_IPC_TYPE_STATUS_RESPONSE 0x80000002u
#define OAC_IPC_TYPE_LAUNCH_RESPONSE 0x80000003u

#define OAC_IPC_STATUS_DRIVER_READY 0x00000001u
#define OAC_IPC_STATUS_SESSION_CLAIMED 0x00000002u
#define OAC_IPC_STATUS_PRIOR_SESSION_LOSS 0x00000004u
#define OAC_IPC_STATUS_SCANNER_ACTIVE 0x00000008u

#define OAC_IPC_LAUNCH_CONFIRMED 0x00000001u
#define OAC_IPC_LAUNCH_JOB_ASSIGNED 0x00000002u
#define OAC_IPC_LAUNCH_RESUMED   0x00000004u

typedef enum OAC_IPC_LAUNCH_STAGE_TAG
{
    OAC_IPC_LAUNCH_STAGE_NONE = 0,
    OAC_IPC_LAUNCH_STAGE_AUTHORIZE_CLIENT = 1,
    OAC_IPC_LAUNCH_STAGE_OPEN_EXECUTABLE = 2,
    OAC_IPC_LAUNCH_STAGE_CREATE_ENVIRONMENT = 3,
    OAC_IPC_LAUNCH_STAGE_ARM_TICKET = 4,
    OAC_IPC_LAUNCH_STAGE_CREATE_PROCESS = 5,
    OAC_IPC_LAUNCH_STAGE_CONFIRM_TARGET = 6,
    OAC_IPC_LAUNCH_STAGE_VALIDATE_STATUS = 7,
    OAC_IPC_LAUNCH_STAGE_ASSIGN_JOB = 8,
    OAC_IPC_LAUNCH_STAGE_RESUME_THREAD = 9,
    OAC_IPC_LAUNCH_STAGE_VERIFY_MANIFEST = 10
} OAC_IPC_LAUNCH_STAGE;

typedef enum OAC_IPC_LAUNCH_DETAIL_TAG
{
    OAC_IPC_LAUNCH_DETAIL_NONE = 0,
    OAC_IPC_LAUNCH_DETAIL_STATUS_UNAVAILABLE = 1,
    OAC_IPC_LAUNCH_DETAIL_CANCELLED = 2,
    OAC_IPC_LAUNCH_DETAIL_EXPIRED = 3,
    OAC_IPC_LAUNCH_DETAIL_PATH_MISMATCH = 4,
    OAC_IPC_LAUNCH_DETAIL_CONFIRMATION_FAILED = 5,
    OAC_IPC_LAUNCH_DETAIL_REQUESTED = 6,
    OAC_IPC_LAUNCH_DETAIL_FILE_CLEANUP = 7,
    OAC_IPC_LAUNCH_DETAIL_SERVICE_EXIT = 8,
    OAC_IPC_LAUNCH_DETAIL_TARGET_EXIT = 9,
    OAC_IPC_LAUNCH_DETAIL_POLICY = 10,
    OAC_IPC_LAUNCH_DETAIL_EVIDENCE_LOSS = 11,
    OAC_IPC_LAUNCH_DETAIL_DRIVER_STOP = 12,
    OAC_IPC_LAUNCH_DETAIL_OTHER_REVOCATION = 13,
    OAC_IPC_LAUNCH_DETAIL_MANIFEST_MISSING = 14,
    OAC_IPC_LAUNCH_DETAIL_MANIFEST_INVALID = 15,
    OAC_IPC_LAUNCH_DETAIL_MANIFEST_SIGNATURE = 16,
    OAC_IPC_LAUNCH_DETAIL_MANIFEST_BUILD = 17,
    OAC_IPC_LAUNCH_DETAIL_MANIFEST_EXPIRED = 18,
    OAC_IPC_LAUNCH_DETAIL_MANIFEST_ROLLBACK = 19,
    OAC_IPC_LAUNCH_DETAIL_BACKEND = 20
} OAC_IPC_LAUNCH_DETAIL;

/*
 * SCM exposes one application-defined service exit code. OAC keeps the high
 * byte as a signature, four bits for the startup stage, and twenty bits for
 * the original Win32 error. The launcher validates this encoding before it
 * displays either value.
 */
#define OAC_SERVICE_FAILURE_MAGIC 0x4F000000u
#define OAC_SERVICE_FAILURE_MAGIC_MASK 0xFF000000u
#define OAC_SERVICE_FAILURE_STAGE_SHIFT 20u
#define OAC_SERVICE_FAILURE_STAGE_MASK 0x00F00000u
#define OAC_SERVICE_FAILURE_ERROR_MASK 0x000FFFFFu

typedef enum OAC_SERVICE_FAILURE_STAGE_TAG
{
    OAC_SERVICE_STAGE_NONE = 0,
    OAC_SERVICE_STAGE_BOOTSTRAP = 1,
    OAC_SERVICE_STAGE_IDENTITY = 2,
    OAC_SERVICE_STAGE_DRIVER_OPEN = 3,
    OAC_SERVICE_STAGE_DRIVER_NEGOTIATE = 4,
    OAC_SERVICE_STAGE_DRIVER_CLAIM = 5,
    OAC_SERVICE_STAGE_DRIVER_STATUS = 6,
    OAC_SERVICE_STAGE_PIPE_CREATE = 7,
    OAC_SERVICE_STAGE_PIPE_THREAD = 8,
    OAC_SERVICE_STAGE_RUNTIME = 9,
    OAC_SERVICE_STAGE_TARGET_JOB = 10,
    OAC_SERVICE_STAGE_BACKEND = 11
} OAC_SERVICE_FAILURE_STAGE;

static inline uint32_t OacEncodeServiceFailure(
    uint32_t stage,
    uint32_t win32Error)
{
    if (stage == OAC_SERVICE_STAGE_NONE ||
        stage > OAC_SERVICE_STAGE_BACKEND ||
        win32Error == 0 || win32Error > OAC_SERVICE_FAILURE_ERROR_MASK)
    {
        return 0;
    }
    return OAC_SERVICE_FAILURE_MAGIC |
        (stage << OAC_SERVICE_FAILURE_STAGE_SHIFT) |
        win32Error;
}

static inline int OacDecodeServiceFailure(
    uint32_t value,
    uint32_t* stage,
    uint32_t* win32Error)
{
    const uint32_t decodedStage =
        (value & OAC_SERVICE_FAILURE_STAGE_MASK) >>
        OAC_SERVICE_FAILURE_STAGE_SHIFT;
    const uint32_t decodedError = value & OAC_SERVICE_FAILURE_ERROR_MASK;

    if (stage == 0 || win32Error == 0 || stage == win32Error ||
        (value & OAC_SERVICE_FAILURE_MAGIC_MASK) != OAC_SERVICE_FAILURE_MAGIC ||
        decodedStage == OAC_SERVICE_STAGE_NONE ||
        decodedStage > OAC_SERVICE_STAGE_BACKEND || decodedError == 0)
    {
        return 0;
    }
    *stage = decodedStage;
    *win32Error = decodedError;
    return 1;
}

typedef struct OAC_IPC_HEADER_TAG
{
    uint32_t Version;
    uint32_t Size;
    uint32_t Type;
    uint32_t Flags;
    uint64_t RequestId;
} OAC_IPC_HEADER;

typedef struct OAC_IPC_REQUEST_TAG
{
    OAC_IPC_HEADER Header;
    uint64_t Reserved;
} OAC_IPC_REQUEST;

typedef enum OAC_IPC_SCAN_STATE_TAG
{
    OAC_IPC_SCAN_UNAVAILABLE = 0,
    OAC_IPC_SCAN_READY = 1,
    OAC_IPC_SCAN_RUNNING = 2,
    OAC_IPC_SCAN_STOPPED = 3,
    OAC_IPC_SCAN_FAILED = 4
} OAC_IPC_SCAN_STATE;

typedef enum OAC_IPC_SCAN_OUTCOME_TAG
{
    OAC_IPC_SCAN_OUTCOME_NONE = 0,
    OAC_IPC_SCAN_OUTCOME_PARTIAL = 1,
    OAC_IPC_SCAN_OUTCOME_SWEEP_COMPLETED = 2,
    OAC_IPC_SCAN_OUTCOME_CANCELLED = 3,
    OAC_IPC_SCAN_OUTCOME_FAILED = 4
} OAC_IPC_SCAN_OUTCOME;

/*
 * Scanner metrics are cumulative for one service process. Times and durations
 * use 100-nanosecond units. A slice is one bounded worker invocation; a sweep
 * is one complete pass over the target's current memory map and thread set.
 */
typedef struct OAC_IPC_SCAN_METRICS_TAG
{
    uint64_t HealthIterations;
    uint64_t MaximumHealthDelay100ns;
    uint64_t SlicesQueued;
    uint64_t SlicesCompleted;
    uint64_t SlicesCoalesced;
    uint64_t SlicesCancelled;
    uint64_t SlicesFailed;
    uint64_t SweepsCompleted;
    uint64_t MemoryRegionsInspected;
    uint64_t MemoryBytesRead;
    uint64_t ThreadsInspected;
    uint64_t ThreadsSkipped;
    uint64_t MaximumSliceDuration100ns;
    uint64_t MaximumThreadSuspension100ns;
    uint64_t LastStartTime100ns;
    uint64_t LastEndTime100ns;
    uint64_t LastCpuTime100ns;
    uint64_t LastBytesRead;
    uint64_t LastItemsInspected;
    uint64_t LastItemsSkipped;
    uint64_t PeakWorkingBufferBytes;
    uint32_t State;
    uint32_t LastOutcome;
    uint32_t LastError;
    uint32_t Reserved;
} OAC_IPC_SCAN_METRICS;

#define OAC_IPC_BACKEND_AUTHENTICATED 0x00000001u
#define OAC_IPC_BACKEND_TEST_DOUBLE   0x00000002u
#define OAC_IPC_BACKEND_FLAGS (OAC_IPC_BACKEND_AUTHENTICATED | \
    OAC_IPC_BACKEND_TEST_DOUBLE)

typedef struct OAC_IPC_BACKEND_STATUS_TAG
{
    uint32_t LeaseState;
    uint32_t Flags;
    uint32_t PendingEvidence;
    uint32_t LastError;
    uint64_t LeaseSequence;
    uint64_t AcknowledgedSequence;
} OAC_IPC_BACKEND_STATUS;

typedef struct OAC_IPC_RESPONSE_TAG
{
    OAC_IPC_HEADER Header;
    uint32_t Win32Error;
    uint32_t StatusFlags;
    uint32_t ServiceProcessId;
    uint32_t ClientProcessId;
    uint32_t ClientSessionId;
    uint32_t DriverProtocolVersion;
    uint64_t DriverCapabilities;
    uint64_t SessionLossSequence;
    uint32_t LastSessionLossReason;
    uint32_t Reserved;
    OAC_IPC_BACKEND_STATUS Backend;
    OAC_IPC_SCAN_METRICS Scanner;
} OAC_IPC_RESPONSE;

typedef struct OAC_IPC_LAUNCH_REQUEST_TAG
{
    OAC_IPC_HEADER Header;
    uint32_t ExecutablePathLength;
    uint32_t Reserved;
    uint16_t ExecutablePath[OAC_IPC_MAX_EXECUTABLE_PATH_CHARS];
} OAC_IPC_LAUNCH_REQUEST;

typedef struct OAC_IPC_LAUNCH_RESPONSE_TAG
{
    OAC_IPC_HEADER Header;
    uint32_t Win32Error;
    uint32_t LaunchFlags;
    uint32_t ServiceProcessId;
    uint32_t ClientProcessId;
    uint32_t ClientSessionId;
    uint32_t TargetProcessId;
    uint32_t FailureStage;
    uint32_t FailureDetail;
} OAC_IPC_LAUNCH_RESPONSE;

static inline int OacIpcHeaderMatches(
    const OAC_IPC_HEADER* header,
    uint32_t bytes,
    uint32_t expectedSize,
    uint32_t expectedType)
{
    return header != 0 && bytes == expectedSize &&
        header->Version == OAC_IPC_PROTOCOL_REVISION &&
        header->Size == expectedSize && header->Type == expectedType &&
        header->Flags == 0 && header->RequestId != 0;
}

static inline int OacIpcScanMetricsAreZero(
    const OAC_IPC_SCAN_METRICS* metrics)
{
    const uint8_t* bytes;
    size_t index;

    if (metrics == 0) return 0;
    bytes = (const uint8_t*)metrics;
    for (index = 0; index < sizeof(*metrics); ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static inline int OacIpcScanMetricsValid(
    const OAC_IPC_SCAN_METRICS* metrics)
{
    if (metrics == 0 || metrics->State > OAC_IPC_SCAN_FAILED ||
        metrics->LastOutcome > OAC_IPC_SCAN_OUTCOME_FAILED ||
        metrics->Reserved != 0 ||
        metrics->SlicesCompleted > metrics->SlicesQueued ||
        metrics->SlicesCancelled >
            metrics->SlicesQueued - metrics->SlicesCompleted ||
        metrics->SlicesFailed >
            metrics->SlicesQueued - metrics->SlicesCompleted -
                metrics->SlicesCancelled ||
        metrics->SweepsCompleted > metrics->SlicesCompleted)
    {
        return 0;
    }

    if (metrics->LastOutcome == OAC_IPC_SCAN_OUTCOME_NONE)
    {
        if (metrics->LastStartTime100ns != 0 ||
            metrics->LastEndTime100ns != 0 ||
            metrics->LastCpuTime100ns != 0 ||
            metrics->LastBytesRead != 0 ||
            metrics->LastItemsInspected != 0 ||
            metrics->LastItemsSkipped != 0 || metrics->LastError != 0)
        {
            return 0;
        }
    }
    else
    {
        if (metrics->LastStartTime100ns == 0 ||
            metrics->LastEndTime100ns < metrics->LastStartTime100ns)
        {
            return 0;
        }
        if ((metrics->LastOutcome == OAC_IPC_SCAN_OUTCOME_PARTIAL ||
             metrics->LastOutcome == OAC_IPC_SCAN_OUTCOME_SWEEP_COMPLETED) !=
            (metrics->LastError == 0))
        {
            return 0;
        }
    }

    if (metrics->State == OAC_IPC_SCAN_UNAVAILABLE &&
        (metrics->SlicesQueued != 0 || metrics->SlicesCompleted != 0 ||
         metrics->SlicesCoalesced != 0 || metrics->SlicesCancelled != 0 ||
         metrics->SlicesFailed != 0 || metrics->SweepsCompleted != 0 ||
         metrics->LastOutcome != OAC_IPC_SCAN_OUTCOME_NONE))
    {
        return 0;
    }
    if (metrics->State == OAC_IPC_SCAN_FAILED &&
        (metrics->LastOutcome != OAC_IPC_SCAN_OUTCOME_FAILED ||
         metrics->LastError == 0))
    {
        return 0;
    }
    return 1;
}

static inline int OacIpcBackendStatusAreZero(
    const OAC_IPC_BACKEND_STATUS* status)
{
    const uint8_t* bytes;
    size_t index;

    if (status == 0) return 0;
    bytes = (const uint8_t*)status;
    for (index = 0; index < sizeof(*status); ++index)
    {
        if (bytes[index] != 0) return 0;
    }
    return 1;
}

static inline int OacIpcBackendStatusValid(
    const OAC_IPC_BACKEND_STATUS* status)
{
    if (status == 0 || status->LeaseState < OAC_LEASE_HEALTHY ||
        status->LeaseState > OAC_LEASE_REVOKED ||
        (status->Flags & ~OAC_IPC_BACKEND_FLAGS) != 0 ||
        (status->Flags & OAC_IPC_BACKEND_AUTHENTICATED) == 0 ||
        status->LeaseSequence == 0)
    {
        return 0;
    }
    if (status->LastError == 0)
    {
        return status->LeaseState == OAC_LEASE_HEALTHY ||
            status->LeaseState == OAC_LEASE_DEGRADED;
    }
    return status->LeaseState == OAC_LEASE_EXPIRED ||
        status->LeaseState == OAC_LEASE_REVOKED;
}

static inline int OacIpcExecutablePathValid(
    const uint16_t* path,
    uint32_t length)
{
    uint32_t index;
    uint32_t componentStart = 3;

    if (path == 0 || length < 4 ||
        length >= OAC_IPC_MAX_EXECUTABLE_PATH_CHARS ||
        !((path[0] >= (uint16_t)'A' && path[0] <= (uint16_t)'Z') ||
          (path[0] >= (uint16_t)'a' && path[0] <= (uint16_t)'z')) ||
        path[1] != (uint16_t)':' || path[2] != (uint16_t)'\\')
    {
        return 0;
    }

    for (index = 3; index < length; ++index)
    {
        const uint16_t value = path[index];
        if (value == 0 || value < 0x20u || value == (uint16_t)'/' ||
            value == (uint16_t)':' || value == (uint16_t)'"' ||
            value == (uint16_t)'*' || value == (uint16_t)'?' ||
            value == (uint16_t)'<' || value == (uint16_t)'>' ||
            value == (uint16_t)'|')
        {
            return 0;
        }
        if (value >= 0xD800u && value <= 0xDBFFu)
        {
            ++index;
            if (index >= length || path[index] < 0xDC00u ||
                path[index] > 0xDFFFu)
            {
                return 0;
            }
            continue;
        }
        if (value >= 0xDC00u && value <= 0xDFFFu) return 0;
        if (value == (uint16_t)'\\')
        {
            const uint32_t componentLength = index - componentStart;
            if (componentLength == 0 || path[index - 1] == (uint16_t)'.' ||
                path[index - 1] == (uint16_t)' ' ||
                (componentLength == 1 &&
                 path[componentStart] == (uint16_t)'.') ||
                (componentLength == 2 &&
                 path[componentStart] == (uint16_t)'.' &&
                 path[componentStart + 1] == (uint16_t)'.'))
            {
                return 0;
            }
            componentStart = index + 1;
        }
    }

    if (componentStart == length || path[length - 1] == (uint16_t)'.' ||
        path[length - 1] == (uint16_t)' ' ||
        (length - componentStart == 1 &&
         path[componentStart] == (uint16_t)'.') ||
        (length - componentStart == 2 &&
         path[componentStart] == (uint16_t)'.' &&
         path[componentStart + 1] == (uint16_t)'.'))
    {
        return 0;
    }
    for (index = length; index < OAC_IPC_MAX_EXECUTABLE_PATH_CHARS; ++index)
    {
        if (path[index] != 0) return 0;
    }
    return 1;
}

static inline int OacIpcValidateLaunchRequest(
    const OAC_IPC_LAUNCH_REQUEST* request,
    uint32_t bytes)
{
    return request != 0 &&
        OacIpcHeaderMatches(
            &request->Header,
            bytes,
            (uint32_t)sizeof(*request),
            OAC_IPC_TYPE_LAUNCH_REQUEST) &&
        request->Reserved == 0 &&
        OacIpcExecutablePathValid(
            request->ExecutablePath,
            request->ExecutablePathLength);
}

static inline int OacIpcValidateLaunchResponse(
    const OAC_IPC_LAUNCH_RESPONSE* response,
    uint32_t bytes,
    uint64_t requestId)
{
    const uint32_t successFlags =
        OAC_IPC_LAUNCH_CONFIRMED | OAC_IPC_LAUNCH_JOB_ASSIGNED |
        OAC_IPC_LAUNCH_RESUMED;

    if (response == 0 || !OacIpcHeaderMatches(
            &response->Header,
            bytes,
            (uint32_t)sizeof(*response),
            OAC_IPC_TYPE_LAUNCH_RESPONSE) ||
        response->Header.RequestId != requestId ||
        response->FailureStage > OAC_IPC_LAUNCH_STAGE_VERIFY_MANIFEST ||
        response->FailureDetail > OAC_IPC_LAUNCH_DETAIL_BACKEND)
    {
        return 0;
    }
    if (response->Win32Error == 0)
    {
        return response->LaunchFlags == successFlags &&
            response->ServiceProcessId != 0 &&
            response->ClientProcessId != 0 &&
            response->ClientSessionId != 0 &&
            response->TargetProcessId != 0 &&
            response->FailureStage == OAC_IPC_LAUNCH_STAGE_NONE &&
            response->FailureDetail == OAC_IPC_LAUNCH_DETAIL_NONE;
    }
    return response->LaunchFlags == 0 &&
        response->ServiceProcessId == 0 &&
        response->ClientProcessId == 0 &&
        response->ClientSessionId == 0 &&
        response->TargetProcessId == 0 &&
        response->FailureStage != OAC_IPC_LAUNCH_STAGE_NONE;
}

#ifdef __cplusplus
#define OAC_IPC_STATIC_ASSERT(Expression, Message) \
    static_assert((Expression), Message)
#else
#define OAC_IPC_STATIC_ASSERT(Expression, Message) \
    _Static_assert((Expression), Message)
#endif

#if defined(__clang__)
#define OAC_IPC_OFFSETOF(Type, Field) __builtin_offsetof(Type, Field)
#else
#define OAC_IPC_OFFSETOF(Type, Field) offsetof(Type, Field)
#endif

OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_HEADER) == 24,
    "OAC_IPC_HEADER layout changed");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_REQUEST) == 32,
    "OAC_IPC_REQUEST layout changed");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_SCAN_METRICS) == 184,
    "OAC_IPC_SCAN_METRICS layout changed");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_SCAN_METRICS, State) == 168,
    "OAC_IPC_SCAN_METRICS state moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_SCAN_METRICS, LastError) == 176,
    "OAC_IPC_SCAN_METRICS error moved");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_BACKEND_STATUS) == 32,
    "OAC_IPC_BACKEND_STATUS layout changed");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_BACKEND_STATUS, LeaseSequence) == 16,
    "OAC_IPC_BACKEND_STATUS sequence moved");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_RESPONSE) == 288,
    "OAC_IPC_RESPONSE layout changed");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_RESPONSE, SessionLossSequence) == 56,
    "OAC_IPC_RESPONSE liveness sequence moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_RESPONSE, LastSessionLossReason) == 64,
    "OAC_IPC_RESPONSE liveness reason moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_RESPONSE, Reserved) == 68,
    "OAC_IPC_RESPONSE reserved field moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_RESPONSE, Backend) == 72,
    "OAC_IPC_RESPONSE backend status moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_RESPONSE, Scanner) == 104,
    "OAC_IPC_RESPONSE scanner metrics moved");
OAC_IPC_STATIC_ASSERT(sizeof(uint16_t) == 2,
    "OAC IPC paths require 16-bit code units");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_LAUNCH_REQUEST) == 1056,
    "OAC_IPC_LAUNCH_REQUEST layout changed");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_LAUNCH_REQUEST, ExecutablePathLength) == 24,
    "OAC_IPC_LAUNCH_REQUEST length moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_LAUNCH_REQUEST, ExecutablePath) == 32,
    "OAC_IPC_LAUNCH_REQUEST path moved");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_LAUNCH_RESPONSE) == 56,
    "OAC_IPC_LAUNCH_RESPONSE layout changed");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_LAUNCH_RESPONSE, TargetProcessId) == 44,
    "OAC_IPC_LAUNCH_RESPONSE target identity moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_LAUNCH_RESPONSE, FailureStage) == 48,
    "OAC_IPC_LAUNCH_RESPONSE failure stage moved");
OAC_IPC_STATIC_ASSERT(
    OAC_IPC_OFFSETOF(OAC_IPC_LAUNCH_RESPONSE, FailureDetail) == 52,
    "OAC_IPC_LAUNCH_RESPONSE failure detail moved");
OAC_IPC_STATIC_ASSERT(
    (OAC_SERVICE_FAILURE_MAGIC_MASK & OAC_SERVICE_FAILURE_STAGE_MASK) == 0 &&
    (OAC_SERVICE_FAILURE_MAGIC_MASK & OAC_SERVICE_FAILURE_ERROR_MASK) == 0 &&
    (OAC_SERVICE_FAILURE_STAGE_MASK & OAC_SERVICE_FAILURE_ERROR_MASK) == 0,
    "service failure fields overlap");
OAC_IPC_STATIC_ASSERT(OAC_SERVICE_STAGE_BACKEND <= 0xFu,
    "service failure stage exceeds its field");

#undef OAC_IPC_STATIC_ASSERT
#undef OAC_IPC_OFFSETOF
