#pragma once

/*
 * Fixed local protocol between the unprivileged launcher and OACService.
 * The pipe is a trust boundary: keep every layout fixed-width and reject
 * messages whose version, size, type, flags, or reserved fields differ.
 */

#include <stdint.h>

#define OAC_IPC_VERSION 0x00010000u
#define OAC_IPC_MAX_MESSAGE_SIZE 4096u

#define OAC_SERVICE_NAME L"OACService"
#define OAC_SERVICE_ACCOUNT L"NT SERVICE\\OACService"
#define OAC_SERVICE_SID \
    L"S-1-5-80-1726785755-3364470821-2652420548-2779146334-590817200"
#define OAC_PIPE_NAME L"\\\\.\\pipe\\OAC.Control"

/* Read/write without FILE_APPEND_DATA, which is FILE_CREATE_PIPE_INSTANCE. */
#define OAC_PIPE_CLIENT_ACCESS 0x0012019Bu

#define OAC_IPC_TYPE_HELLO_REQUEST 0x00000001u
#define OAC_IPC_TYPE_STATUS_REQUEST 0x00000002u
#define OAC_IPC_TYPE_HELLO_RESPONSE 0x80000001u
#define OAC_IPC_TYPE_STATUS_RESPONSE 0x80000002u

#define OAC_IPC_STATUS_DRIVER_READY 0x00000001u
#define OAC_IPC_STATUS_SESSION_CLAIMED 0x00000002u

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
    OAC_SERVICE_STAGE_RUNTIME = 9
} OAC_SERVICE_FAILURE_STAGE;

static inline uint32_t OacEncodeServiceFailure(
    uint32_t stage,
    uint32_t win32Error)
{
    if (stage == OAC_SERVICE_STAGE_NONE ||
        stage > OAC_SERVICE_STAGE_RUNTIME ||
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
        decodedStage > OAC_SERVICE_STAGE_RUNTIME || decodedError == 0)
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
} OAC_IPC_RESPONSE;

#ifdef __cplusplus
#define OAC_IPC_STATIC_ASSERT(Expression, Message) \
    static_assert((Expression), Message)
#else
#define OAC_IPC_STATIC_ASSERT(Expression, Message) \
    _Static_assert((Expression), Message)
#endif

OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_HEADER) == 24,
    "OAC_IPC_HEADER layout changed");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_REQUEST) == 32,
    "OAC_IPC_REQUEST layout changed");
OAC_IPC_STATIC_ASSERT(sizeof(OAC_IPC_RESPONSE) == 56,
    "OAC_IPC_RESPONSE layout changed");
OAC_IPC_STATIC_ASSERT(
    (OAC_SERVICE_FAILURE_MAGIC_MASK & OAC_SERVICE_FAILURE_STAGE_MASK) == 0 &&
    (OAC_SERVICE_FAILURE_MAGIC_MASK & OAC_SERVICE_FAILURE_ERROR_MASK) == 0 &&
    (OAC_SERVICE_FAILURE_STAGE_MASK & OAC_SERVICE_FAILURE_ERROR_MASK) == 0,
    "service failure fields overlap");
OAC_IPC_STATIC_ASSERT(OAC_SERVICE_STAGE_RUNTIME <= 0xFu,
    "service failure stage exceeds its field");

#undef OAC_IPC_STATIC_ASSERT
