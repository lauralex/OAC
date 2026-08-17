#include "../../shared/oac_ipc.h"
#include "../../shared/protocol/oac_v5.h"
#include "../../shared/protocol/oac_validate.h"

_Static_assert(sizeof(OAC_V5_REQUEST_HEADER) == 48,
    "C request-header layout changed");
_Static_assert(sizeof(OAC_V5_NEGOTIATE_RESPONSE) == 88,
    "C negotiate-response layout changed");
_Static_assert(FIELD_OFFSET(OAC_V5_REQUEST_HEADER, MessageType) == 44,
    "C request message type moved");
_Static_assert(FIELD_OFFSET(OAC_V5_RESPONSE_HEADER, MessageType) == 52,
    "C response message type moved");
_Static_assert(FIELD_OFFSET(OAC_V5_EVENT_RECORD, Text) == 176,
    "C event prefix layout changed");
_Static_assert(sizeof(OAC_V5_EVENT_RECORD) == 560,
    "C event-record layout changed");
_Static_assert(sizeof(OAC_ARM_LAUNCH_REQUEST) == 2112,
    "C arm-launch request layout changed");
_Static_assert(FIELD_OFFSET(OAC_ARM_LAUNCH_REQUEST,
    CanonicalNtPath) == 64, "C arm-launch path moved");
_Static_assert(FIELD_OFFSET(OAC_ARM_LAUNCH_REQUEST,
    CanonicalDosDevicePath) == 1088,
    "C arm-launch DOS-device path moved");
_Static_assert(sizeof(OAC_CONFIRM_TARGET_REQUEST) == 72,
    "C confirm-target request layout changed");
_Static_assert(sizeof(OAC_IPC_LAUNCH_REQUEST) == 1056,
    "C service launch request layout changed");
_Static_assert(sizeof(OAC_IPC_LAUNCH_RESPONSE) == 56,
    "C service launch response layout changed");

int OacV5CProbe(void)
{
    OAC_V5_NEGOTIATE_REQUEST request = { 0 };
    OAC_LAUNCH_ID launchId = { 1, 2 };
    UCHAR reserved[4] = { 0 };
    uint32_t failureStage = 0;
    uint32_t failureError = 0;
    OAC_IPC_LAUNCH_REQUEST launchRequest = { 0 };

    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = 1;
    request.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    request.MinimumVersion = OAC_V5_VERSION;
    request.MaximumVersion = OAC_V5_VERSION;

    launchRequest.Header.Version = OAC_IPC_PROTOCOL_REVISION;
    launchRequest.Header.Size = sizeof(launchRequest);
    launchRequest.Header.Type = OAC_IPC_TYPE_LAUNCH_REQUEST;
    launchRequest.Header.RequestId = 1;
    launchRequest.ExecutablePathLength = 11;
    launchRequest.ExecutablePath[0] = 'C';
    launchRequest.ExecutablePath[1] = ':';
    launchRequest.ExecutablePath[2] = '\\';
    launchRequest.ExecutablePath[3] = 'G';
    launchRequest.ExecutablePath[4] = 'a';
    launchRequest.ExecutablePath[5] = 'm';
    launchRequest.ExecutablePath[6] = 'e';
    launchRequest.ExecutablePath[7] = '.';
    launchRequest.ExecutablePath[8] = 'e';
    launchRequest.ExecutablePath[9] = 'x';
    launchRequest.ExecutablePath[10] = 'e';

    return OacV5ValidateNegotiateRequest(&request, sizeof(request)) == OAC_V5_VALID &&
        OacV5ValidateReserved(reserved, sizeof(reserved)) == OAC_V5_VALID &&
        OacIpcValidateLaunchRequest(
            &launchRequest,
            sizeof(launchRequest)) != 0 &&
        OacV5ValidateRange(64, 32, 4, 8, 32, 8) == OAC_V5_VALID &&
        OacDecodeServiceFailure(
            OacEncodeServiceFailure(
                OAC_SERVICE_STAGE_DRIVER_OPEN,
                5),
            &failureStage,
            &failureError) != 0 &&
        failureStage == OAC_SERVICE_STAGE_DRIVER_OPEN && failureError == 5 &&
        OacV5SessionTransitionValid(
            OAC_V5_SESSION_CLAIMED,
            OAC_V5_SESSION_LAUNCH_PENDING) != FALSE &&
        OacValidateLaunchId(&launchId) == OAC_V5_VALID &&
        OacDecideLaunchCandidate(
            OAC_V5_SESSION_LAUNCH_PENDING,
            1,
            2,
            TRUE,
            TRUE,
            TRUE) == OAC_LAUNCH_CONSUME_BIND;
}
