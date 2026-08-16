#pragma once

#include "oac_v5.h"

/* Pure validation results; callers map these to transport-specific status. */
typedef ULONG OAC_V5_VALIDATION;

#define OAC_V5_VALID                 0UL
#define OAC_V5_INVALID_POINTER       1UL
#define OAC_V5_INVALID_LENGTH        2UL
#define OAC_V5_INVALID_VERSION       3UL
#define OAC_V5_INVALID_REQUEST_ID    4UL
#define OAC_V5_INVALID_FLAGS         5UL
#define OAC_V5_INVALID_RESERVED      6UL
#define OAC_V5_INVALID_SESSION       7UL
#define OAC_V5_INVALID_GENERATION    8UL
#define OAC_V5_INVALID_RANGE         9UL
#define OAC_V5_INVALID_ALIGNMENT     10UL
#define OAC_V5_INVALID_VALUE         11UL
#define OAC_V5_INVALID_CORRELATION   12UL
#define OAC_V5_INVALID_MESSAGE_TYPE  13UL

typedef ULONG OAC_V5_ID_REQUIREMENT;
#define OAC_V5_ID_ANY      0UL
#define OAC_V5_ID_ZERO     1UL
#define OAC_V5_ID_REQUIRED 2UL

static __inline BOOLEAN OacV5SessionIdIsZero(
    const OAC_V5_SESSION_ID* SessionId)
{
    return SessionId != NULL && SessionId->High == 0 && SessionId->Low == 0;
}

static __inline BOOLEAN OacV5SessionIdEqual(
    const OAC_V5_SESSION_ID* Left,
    const OAC_V5_SESSION_ID* Right)
{
    return Left != NULL && Right != NULL &&
        Left->High == Right->High && Left->Low == Right->Low;
}

static __inline OAC_V5_VALIDATION OacV5ValidateVersion(ULONG Version)
{
    return Version == OAC_V5_VERSION ? OAC_V5_VALID : OAC_V5_INVALID_VERSION;
}

static __inline BOOLEAN OacV5MessageTypeValid(
    OAC_V5_MESSAGE_TYPE MessageType)
{
    return MessageType >= OAC_V5_MESSAGE_NEGOTIATE &&
        MessageType <= OAC_V5_MESSAGE_REVOKE_SESSION;
}

static __inline OAC_V5_VALIDATION OacV5ValidateSize(
    ULONG ActualSize,
    ULONG StatedSize,
    ULONG MinimumSize,
    ULONG MaximumSize)
{
    if (MinimumSize > MaximumSize || ActualSize < MinimumSize ||
        ActualSize > MaximumSize || StatedSize != ActualSize)
    {
        return OAC_V5_INVALID_LENGTH;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateFlags(
    ULONG Flags,
    ULONG AllowedFlags)
{
    return (Flags & ~AllowedFlags) == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_FLAGS;
}

static __inline OAC_V5_VALIDATION OacV5ValidateReserved(
    const VOID* Buffer,
    ULONG Size)
{
    const UCHAR* bytes = (const UCHAR*)Buffer;
    ULONG index;

    if (Size == 0) return OAC_V5_VALID;
    if (bytes == NULL) return OAC_V5_INVALID_POINTER;
    for (index = 0; index < Size; ++index)
    {
        if (bytes[index] != 0) return OAC_V5_INVALID_RESERVED;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateSession(
    const OAC_V5_SESSION_ID* SessionId,
    ULONGLONG Generation,
    OAC_V5_ID_REQUIREMENT Requirement)
{
    BOOLEAN zero;

    if (SessionId == NULL) return OAC_V5_INVALID_POINTER;
    zero = OacV5SessionIdIsZero(SessionId);
    if (Requirement == OAC_V5_ID_ZERO)
    {
        if (!zero) return OAC_V5_INVALID_SESSION;
        return Generation == 0 ? OAC_V5_VALID : OAC_V5_INVALID_GENERATION;
    }
    if (Requirement == OAC_V5_ID_REQUIRED)
    {
        if (zero) return OAC_V5_INVALID_SESSION;
        return Generation != 0 ? OAC_V5_VALID : OAC_V5_INVALID_GENERATION;
    }
    if (Requirement != OAC_V5_ID_ANY) return OAC_V5_INVALID_VALUE;
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateRange(
    ULONG TotalSize,
    ULONG Offset,
    ULONG Count,
    ULONG ElementSize,
    ULONG MinimumOffset,
    ULONG Alignment)
{
    ULONG bytes;

    if (ElementSize == 0 || Alignment == 0 ||
        (Alignment & (Alignment - 1)) != 0)
    {
        return OAC_V5_INVALID_VALUE;
    }
    if ((Offset & (Alignment - 1)) != 0)
    {
        return OAC_V5_INVALID_ALIGNMENT;
    }
    if (Offset < MinimumOffset || Offset > TotalSize ||
        Count > OAC_V5_ULONG_MAX / ElementSize)
    {
        return OAC_V5_INVALID_RANGE;
    }
    bytes = Count * ElementSize;
    if (bytes > TotalSize - Offset) return OAC_V5_INVALID_RANGE;
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateRequestHeader(
    const OAC_V5_REQUEST_HEADER* Header,
    ULONG InputLength,
    ULONG ExpectedSize,
    OAC_V5_MESSAGE_TYPE ExpectedMessageType,
    ULONG AllowedFlags,
    OAC_V5_ID_REQUIREMENT IdRequirement)
{
    OAC_V5_VALIDATION result;

    if (Header == NULL) return OAC_V5_INVALID_POINTER;
    if (InputLength < sizeof(*Header)) return OAC_V5_INVALID_LENGTH;
    result = OacV5ValidateSize(InputLength, Header->Size,
        ExpectedSize, ExpectedSize);
    if (result != OAC_V5_VALID) return result;
    result = OacV5ValidateVersion(Header->Version);
    if (result != OAC_V5_VALID) return result;
    if (Header->RequestId == 0) return OAC_V5_INVALID_REQUEST_ID;
    if (!OacV5MessageTypeValid(ExpectedMessageType) ||
        Header->MessageType != ExpectedMessageType)
    {
        return OAC_V5_INVALID_MESSAGE_TYPE;
    }
    result = OacV5ValidateFlags(Header->Flags, AllowedFlags);
    if (result != OAC_V5_VALID) return result;
    return OacV5ValidateSession(
        &Header->SessionId,
        Header->Generation,
        IdRequirement);
}

static __inline OAC_V5_VALIDATION OacV5ValidateOpenRequest(
    const OAC_V5_REQUEST_HEADER* Header,
    ULONG InputLength,
    ULONG ExpectedSize,
    OAC_V5_MESSAGE_TYPE ExpectedMessageType,
    ULONG AllowedFlags)
{
    return OacV5ValidateRequestHeader(Header, InputLength, ExpectedSize,
        ExpectedMessageType, AllowedFlags, OAC_V5_ID_ZERO);
}

static __inline OAC_V5_VALIDATION OacV5ValidateSessionRequest(
    const OAC_V5_REQUEST_HEADER* Header,
    ULONG InputLength,
    ULONG ExpectedSize,
    OAC_V5_MESSAGE_TYPE ExpectedMessageType,
    ULONG AllowedFlags)
{
    return OacV5ValidateRequestHeader(Header, InputLength, ExpectedSize,
        ExpectedMessageType, AllowedFlags, OAC_V5_ID_REQUIRED);
}

static __inline BOOLEAN OacV5ReasonValid(OAC_V5_REASON Reason)
{
    return Reason <= OAC_V5_REASON_MALFORMED_REQUEST;
}

static __inline OAC_V5_VALIDATION OacV5ValidateResponseHeader(
    const OAC_V5_RESPONSE_HEADER* Header,
    ULONG OutputLength,
    ULONG ExpectedSize,
    OAC_V5_MESSAGE_TYPE ExpectedMessageType,
    ULONG AllowedFlags,
    OAC_V5_ID_REQUIREMENT IdRequirement)
{
    OAC_V5_VALIDATION result;

    if (Header == NULL) return OAC_V5_INVALID_POINTER;
    if (OutputLength < sizeof(*Header)) return OAC_V5_INVALID_LENGTH;
    result = OacV5ValidateSize(OutputLength, Header->Size,
        ExpectedSize, ExpectedSize);
    if (result != OAC_V5_VALID) return result;
    result = OacV5ValidateVersion(Header->Version);
    if (result != OAC_V5_VALID) return result;
    if (Header->RequestId == 0) return OAC_V5_INVALID_REQUEST_ID;
    if (!OacV5MessageTypeValid(ExpectedMessageType) ||
        Header->MessageType != ExpectedMessageType)
    {
        return OAC_V5_INVALID_MESSAGE_TYPE;
    }
    result = OacV5ValidateFlags(Header->Flags, AllowedFlags);
    if (result != OAC_V5_VALID) return result;
    if (!OacV5ReasonValid(Header->Reason)) return OAC_V5_INVALID_VALUE;
    return OacV5ValidateSession(
        &Header->SessionId,
        Header->Generation,
        IdRequirement);
}

static __inline OAC_V5_VALIDATION OacV5ValidateCorrelation(
    const OAC_V5_REQUEST_HEADER* Request,
    const OAC_V5_RESPONSE_HEADER* Response)
{
    if (Request == NULL || Response == NULL) return OAC_V5_INVALID_POINTER;
    if (!OacV5MessageTypeValid(Request->MessageType) ||
        Request->MessageType != Response->MessageType ||
        Request->RequestId != Response->RequestId ||
        Request->Generation != Response->Generation ||
        !OacV5SessionIdEqual(&Request->SessionId, &Response->SessionId))
    {
        return OAC_V5_INVALID_CORRELATION;
    }
    return OAC_V5_VALID;
}

static __inline BOOLEAN OacV5SessionStateValid(OAC_V5_SESSION_STATE State)
{
    return State <= OAC_V5_SESSION_CLOSING;
}

static __inline BOOLEAN OacV5SessionTransitionValid(
    OAC_V5_SESSION_STATE From,
    OAC_V5_SESSION_STATE To)
{
    /* Session state changes are strict: retries do not create self-edges. */
    if (!OacV5SessionStateValid(From) ||
        !OacV5SessionStateValid(To))
    {
        return FALSE;
    }

    switch (From)
    {
    case OAC_V5_SESSION_CLAIMED:
        return To == OAC_V5_SESSION_LAUNCH_PENDING ||
            To == OAC_V5_SESSION_REVOKED ||
            To == OAC_V5_SESSION_CLOSING;
    case OAC_V5_SESSION_LAUNCH_PENDING:
        return To == OAC_V5_SESSION_TARGET_BOUND ||
            To == OAC_V5_SESSION_REVOKED ||
            To == OAC_V5_SESSION_CLOSING;
    case OAC_V5_SESSION_TARGET_BOUND:
        return To == OAC_V5_SESSION_MONITORING ||
            To == OAC_V5_SESSION_REVOKED ||
            To == OAC_V5_SESSION_CLOSING;
    case OAC_V5_SESSION_MONITORING:
        return To == OAC_V5_SESSION_REVOKED ||
            To == OAC_V5_SESSION_CLOSING;
    case OAC_V5_SESSION_REVOKED:
        return To == OAC_V5_SESSION_CLOSING;
    default:
        return FALSE;
    }
}

static __inline BOOLEAN OacV5RevokeReasonValid(OAC_V5_REVOKE_REASON Reason)
{
    return Reason <= OAC_V5_REVOKE_DRIVER_STOP;
}

static __inline BOOLEAN OacV5RuleIdValid(OAC_V5_RULE_ID RuleId)
{
    ULONG group = RuleId & OAC_V5_RULE_GROUP_MASK;
    ULONG code = RuleId & OAC_V5_RULE_CODE_MASK;
    return code != 0 && group >= OAC_V5_RULE_SESSION_BASE &&
        group <= OAC_V5_RULE_DEVICE_BASE;
}

static __inline BOOLEAN OacV5EventTypeValid(OAC_V5_EVENT_TYPE EventType)
{
    return EventType >= OAC_V5_EVENT_OBSERVATION &&
        EventType <= OAC_V5_EVENT_REVOCATION;
}

static __inline BOOLEAN OacV5ObservationSeverityValid(
    OAC_V5_OBSERVATION_SEVERITY Severity)
{
    return Severity <= OAC_V5_OBSERVATION_CRITICAL;
}

static __inline BOOLEAN OacV5PolicySeverityValid(
    OAC_V5_POLICY_SEVERITY Severity)
{
    return Severity == OAC_V5_POLICY_NOT_EVALUATED ||
        (Severity >= OAC_V5_POLICY_INFO &&
         Severity <= OAC_V5_POLICY_CRITICAL);
}

static __inline BOOLEAN OacV5ConfidenceValid(OAC_V5_CONFIDENCE Confidence)
{
    return Confidence <= OAC_V5_CONFIDENCE_HIGH;
}

static __inline BOOLEAN OacV5PayloadTypeValid(OAC_V5_PAYLOAD_TYPE PayloadType)
{
    return PayloadType <= OAC_V5_PAYLOAD_UTF16;
}

static __inline BOOLEAN OacV5CategoryValid(OAC_V5_CATEGORY Category)
{
    return Category <= OAC_V5_CATEGORY_HWID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateEventPayload(
    const OAC_V5_EVENT_RECORD* Record)
{
    const UCHAR* bytes;
    ULONG capacity;
    ULONG units;
    ULONG index;

    if (Record == NULL) return OAC_V5_INVALID_POINTER;
    bytes = (const UCHAR*)Record->Text;
    capacity = (ULONG)sizeof(Record->Text);
    if (!OacV5PayloadTypeValid(Record->PayloadType))
    {
        return OAC_V5_INVALID_VALUE;
    }
    if (Record->PayloadLength > capacity)
    {
        return OAC_V5_INVALID_RANGE;
    }

    if (Record->PayloadType == OAC_V5_PAYLOAD_NONE)
    {
        if (Record->PayloadLength != 0) return OAC_V5_INVALID_LENGTH;
    }
    else if (Record->PayloadType == OAC_V5_PAYLOAD_BINARY)
    {
        if (Record->PayloadLength == 0) return OAC_V5_INVALID_LENGTH;
    }
    else
    {
        if (Record->PayloadLength < sizeof(WCHAR))
        {
            return OAC_V5_INVALID_LENGTH;
        }
        if ((Record->PayloadLength & (sizeof(WCHAR) - 1)) != 0)
        {
            return OAC_V5_INVALID_ALIGNMENT;
        }
        units = Record->PayloadLength / sizeof(WCHAR);
        if (Record->Text[units - 1] != L'\0') return OAC_V5_INVALID_VALUE;
        for (index = 0; index + 1 < units; ++index)
        {
            USHORT value = (USHORT)Record->Text[index];
            if (value == 0) return OAC_V5_INVALID_VALUE;
            if (value >= 0xD800 && value <= 0xDBFF)
            {
                USHORT low;
                if (index + 2 >= units) return OAC_V5_INVALID_VALUE;
                low = (USHORT)Record->Text[index + 1];
                if (low < 0xDC00 || low > 0xDFFF)
                {
                    return OAC_V5_INVALID_VALUE;
                }
                ++index;
            }
            else if (value >= 0xDC00 && value <= 0xDFFF)
            {
                return OAC_V5_INVALID_VALUE;
            }
        }
    }

    return OacV5ValidateReserved(
        bytes + Record->PayloadLength,
        capacity - Record->PayloadLength);
}

static __inline OAC_V5_VALIDATION OacV5ValidateEventRecord(
    const OAC_V5_EVENT_RECORD* Record,
    ULONG RecordLength)
{
    OAC_V5_VALIDATION result;

    if (Record == NULL) return OAC_V5_INVALID_POINTER;
    if (RecordLength < sizeof(*Record)) return OAC_V5_INVALID_LENGTH;
    result = OacV5ValidateSize(
        RecordLength,
        Record->Size,
        sizeof(*Record),
        sizeof(*Record));
    if (result != OAC_V5_VALID) return result;
    result = OacV5ValidateVersion(Record->Version);
    if (result != OAC_V5_VALID) return result;
    if (!OacV5RuleIdValid(Record->RuleId) ||
        !OacV5EventTypeValid(Record->EventType) ||
        !OacV5ObservationSeverityValid(Record->ObservationSeverity) ||
        !OacV5PolicySeverityValid(Record->PolicySeverity) ||
        !OacV5ConfidenceValid(Record->Confidence) ||
        !OacV5CategoryValid(Record->Category))
    {
        return OAC_V5_INVALID_VALUE;
    }
    if (Record->Reserved != 0) return OAC_V5_INVALID_RESERVED;
    if (Record->EventType == OAC_V5_EVENT_POLICY_VIOLATION &&
        Record->PolicySeverity == OAC_V5_POLICY_NOT_EVALUATED)
    {
        return OAC_V5_INVALID_VALUE;
    }
    result = OacV5ValidateSession(
        &Record->SessionId,
        Record->Generation,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if ((Record->EvidenceFlags & ~OAC_V5_EVIDENCE_FLAGS) != 0 ||
        OacV5ValidateFlags(Record->Flags, OAC_V5_EVENT_FLAGS) != OAC_V5_VALID)
    {
        return OAC_V5_INVALID_FLAGS;
    }
    if (Record->Sequence == 0 || Record->Timestamp100ns == 0 ||
        Record->OccurrenceCount == 0 ||
        Record->FirstOccurrence100ns == 0 ||
        Record->LastOccurrence100ns == 0 ||
        Record->FirstOccurrence100ns > Record->Timestamp100ns ||
        Record->Timestamp100ns > Record->LastOccurrence100ns ||
        ((Record->IngestionTimestamp100ns == 0) !=
         (Record->ServiceSequence == 0)) ||
        (Record->IngestionTimestamp100ns != 0 &&
         Record->IngestionTimestamp100ns < Record->Timestamp100ns))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OacV5ValidateEventPayload(Record);
}

static __inline OAC_V5_VALIDATION OacV5ValidateNegotiateRequest(
    const OAC_V5_NEGOTIATE_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateOpenRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_V5_MESSAGE_NEGOTIATE, 0);
    if (result != OAC_V5_VALID) return result;
    if (Request->MinimumVersion > Request->MaximumVersion ||
        Request->MinimumVersion > OAC_V5_VERSION ||
        Request->MaximumVersion < OAC_V5_VERSION)
    {
        return OAC_V5_INVALID_VERSION;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateClaimRequest(
    const OAC_V5_CLAIM_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateOpenRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_V5_MESSAGE_CLAIM_SESSION, 0);
    if (result != OAC_V5_VALID) return result;
    if (Request->Reserved != 0) return OAC_V5_INVALID_RESERVED;
    if (Request->Mode != OAC_V5_SESSION_PRODUCTION &&
        Request->Mode != OAC_V5_SESSION_DIAGNOSTIC)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateStatusRequest(
    const OAC_V5_STATUS_REQUEST* Request,
    ULONG InputLength)
{
    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    return OacV5ValidateSessionRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_V5_MESSAGE_GET_STATUS, 0);
}

static __inline OAC_V5_VALIDATION OacV5ValidateNegotiateResponse(
    const OAC_V5_NEGOTIATE_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_V5_MESSAGE_NEGOTIATE, 0, OAC_V5_ID_ZERO);
    if (result != OAC_V5_VALID) return result;
    if (Response->MinimumVersion > Response->SelectedVersion ||
        Response->SelectedVersion > Response->MaximumVersion ||
        Response->SelectedVersion != OAC_V5_VERSION ||
        OacV5ValidateFlags(Response->Capabilities, OAC_V5_CAP_ALL) != OAC_V5_VALID ||
        OacV5ValidateFlags(Response->ProtocolFlags, OAC_V5_PROTOCOL_FLAGS) != OAC_V5_VALID ||
        Response->MaximumInputSize < sizeof(OAC_V5_CLAIM_REQUEST) ||
        Response->MaximumInputSize > OAC_V5_MAX_INPUT_SIZE ||
        Response->MaximumOutputSize < sizeof(OAC_V5_STATUS_RESPONSE) ||
        Response->MaximumOutputSize > OAC_V5_MAX_OUTPUT_SIZE ||
        Response->MaximumEventCount == 0 ||
        Response->MaximumEventCount > OAC_V5_MAX_EVENT_COUNT)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateClaimResponse(
    const OAC_V5_CLAIM_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_V5_MESSAGE_CLAIM_SESSION, 0,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (Response->State != OAC_V5_SESSION_CLAIMED ||
        OacV5ValidateFlags(Response->Capabilities, OAC_V5_CAP_ALL) != OAC_V5_VALID)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacV5ValidateStatusResponse(
    const OAC_V5_STATUS_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_V5_MESSAGE_GET_STATUS,
        OAC_V5_RESPONSE_REVOKED, OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (!OacV5SessionStateValid(Response->State) ||
        Response->State < OAC_V5_SESSION_CLAIMED ||
        !OacV5RevokeReasonValid(Response->RevokeReason) ||
        OacV5ValidateFlags(Response->Capabilities, OAC_V5_CAP_ALL) != OAC_V5_VALID ||
        OacV5ValidateFlags(Response->ConfigurationFlags,
            OAC_V5_CONFIG_FLAGS) != OAC_V5_VALID)
    {
        return OAC_V5_INVALID_VALUE;
    }
    if ((Response->State < OAC_V5_SESSION_REVOKED) !=
        (Response->RevokeReason == OAC_V5_REVOKE_NONE) ||
        ((Response->State >= OAC_V5_SESSION_REVOKED) !=
         ((Response->Header.Flags & OAC_V5_RESPONSE_REVOKED) != 0)))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}
