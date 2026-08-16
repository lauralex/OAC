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

int OacV5CProbe(void)
{
    OAC_V5_NEGOTIATE_REQUEST request = { 0 };
    UCHAR reserved[4] = { 0 };

    request.Header.Version = OAC_V5_VERSION;
    request.Header.Size = sizeof(request);
    request.Header.RequestId = 1;
    request.Header.MessageType = OAC_V5_MESSAGE_NEGOTIATE;
    request.MinimumVersion = OAC_V5_VERSION;
    request.MaximumVersion = OAC_V5_VERSION;

    return OacV5ValidateNegotiateRequest(&request, sizeof(request)) == OAC_V5_VALID &&
        OacV5ValidateReserved(reserved, sizeof(reserved)) == OAC_V5_VALID &&
        OacV5ValidateRange(64, 32, 4, 8, 32, 8) == OAC_V5_VALID &&
        OacV5SessionTransitionValid(
            OAC_V5_SESSION_CLAIMED,
            OAC_V5_SESSION_LAUNCH_PENDING) != FALSE;
}
