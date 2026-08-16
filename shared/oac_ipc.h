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

#undef OAC_IPC_STATIC_ASSERT
