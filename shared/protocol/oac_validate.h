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

static __inline BOOLEAN OacLaunchIdIsZero(
    const OAC_LAUNCH_ID* LaunchId)
{
    return LaunchId != NULL && LaunchId->High == 0 && LaunchId->Low == 0;
}

static __inline BOOLEAN OacLaunchIdEqual(
    const OAC_LAUNCH_ID* Left,
    const OAC_LAUNCH_ID* Right)
{
    return Left != NULL && Right != NULL &&
        Left->High == Right->High && Left->Low == Right->Low;
}

static __inline OAC_V5_VALIDATION OacValidateLaunchId(
    const OAC_LAUNCH_ID* LaunchId)
{
    if (LaunchId == NULL) return OAC_V5_INVALID_POINTER;
    return OacLaunchIdIsZero(LaunchId)
        ? OAC_V5_INVALID_VALUE
        : OAC_V5_VALID;
}

static __inline BOOLEAN OacSnapshotIdIsZero(
    const OAC_SNAPSHOT_ID* SnapshotId)
{
    return SnapshotId != NULL &&
        SnapshotId->High == 0 && SnapshotId->Low == 0;
}

static __inline BOOLEAN OacSnapshotIdEqual(
    const OAC_SNAPSHOT_ID* Left,
    const OAC_SNAPSHOT_ID* Right)
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
        MessageType <= OAC_MESSAGE_CONFIRM_TARGET;
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

static __inline BOOLEAN OacV5BufferIsZero(
    const VOID* Buffer,
    ULONG Size)
{
    const UCHAR* bytes = (const UCHAR*)Buffer;
    ULONG index;

    if (bytes == NULL || Size == 0) return TRUE;
    for (index = 0; index < Size; ++index)
    {
        if (bytes[index] != 0) return FALSE;
    }
    return TRUE;
}

static __inline OAC_V5_VALIDATION OacValidateCanonicalNtPath(
    const WCHAR* Path,
    ULONG PathLength)
{
    ULONG componentStart;
    ULONG index;

    if (Path == NULL) return OAC_V5_INVALID_POINTER;
    if (PathLength <= 8 ||
        PathLength >= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS)
    {
        return OAC_V5_INVALID_RANGE;
    }
    if (Path[0] != L'\\' || Path[1] != L'D' || Path[2] != L'e' ||
        Path[3] != L'v' || Path[4] != L'i' || Path[5] != L'c' ||
        Path[6] != L'e' ||
        Path[7] != L'\\' || Path[PathLength - 1] == L'\\')
    {
        return OAC_V5_INVALID_VALUE;
    }

    componentStart = 1;
    for (index = 0; index < PathLength; ++index)
    {
        const WCHAR value = Path[index];

        if (value == L'\0' || value < 0x20 || value == 0x7f ||
            value == L'/' || value == L':')
        {
            return OAC_V5_INVALID_VALUE;
        }
        if (value == L'\\')
        {
            ULONG componentLength;

            if (index == 0) continue;
            if (index == componentStart) return OAC_V5_INVALID_VALUE;
            componentLength = index - componentStart;
            if (Path[index - 1] == L'.' || Path[index - 1] == L' ')
            {
                return OAC_V5_INVALID_VALUE;
            }
            if ((componentLength == 1 && Path[componentStart] == L'.') ||
                (componentLength == 2 && Path[componentStart] == L'.' &&
                 Path[componentStart + 1] == L'.'))
            {
                return OAC_V5_INVALID_VALUE;
            }
            componentStart = index + 1;
            continue;
        }
        if (value >= 0xd800 && value <= 0xdbff)
        {
            if (index + 1 >= PathLength ||
                Path[index + 1] < 0xdc00 || Path[index + 1] > 0xdfff)
            {
                return OAC_V5_INVALID_VALUE;
            }
            ++index;
        }
        else if (value >= 0xdc00 && value <= 0xdfff)
        {
            return OAC_V5_INVALID_VALUE;
        }
    }

    if (Path[PathLength - 1] == L'.' || Path[PathLength - 1] == L' ' ||
        (PathLength - componentStart == 1 &&
         Path[componentStart] == L'.') ||
        (PathLength - componentStart == 2 &&
         Path[componentStart] == L'.' &&
         Path[componentStart + 1] == L'.'))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OacV5ValidateReserved(
        &Path[PathLength],
        (OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS - PathLength) * sizeof(WCHAR));
}

static __inline OAC_V5_VALIDATION OacValidateCanonicalDosDevicePath(
    const WCHAR* Path,
    ULONG PathLength)
{
    ULONG componentStart = 7;
    ULONG index;

    if (Path == NULL) return OAC_V5_INVALID_POINTER;
    if (PathLength <= componentStart ||
        PathLength >= OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS)
    {
        return OAC_V5_INVALID_RANGE;
    }
    if (Path[0] != L'\\' || Path[1] != L'?' || Path[2] != L'?' ||
        Path[3] != L'\\' ||
        !((Path[4] >= L'A' && Path[4] <= L'Z') ||
          (Path[4] >= L'a' && Path[4] <= L'z')) ||
        Path[5] != L':' || Path[6] != L'\\' ||
        Path[PathLength - 1] == L'\\')
    {
        return OAC_V5_INVALID_VALUE;
    }

    for (index = componentStart; index < PathLength; ++index)
    {
        const WCHAR value = Path[index];

        if (value == L'\0' || value < 0x20 || value == 0x7f ||
            value == L'/' || value == L':' || value == L'"' ||
            value == L'*' || value == L'?' || value == L'<' ||
            value == L'>' || value == L'|')
        {
            return OAC_V5_INVALID_VALUE;
        }
        if (value == L'\\')
        {
            ULONG componentLength;

            if (index == componentStart) return OAC_V5_INVALID_VALUE;
            componentLength = index - componentStart;
            if (Path[index - 1] == L'.' || Path[index - 1] == L' ' ||
                (componentLength == 1 && Path[componentStart] == L'.') ||
                (componentLength == 2 && Path[componentStart] == L'.' &&
                 Path[componentStart + 1] == L'.'))
            {
                return OAC_V5_INVALID_VALUE;
            }
            componentStart = index + 1;
            continue;
        }
        if (value >= 0xd800 && value <= 0xdbff)
        {
            if (index + 1 >= PathLength ||
                Path[index + 1] < 0xdc00 || Path[index + 1] > 0xdfff)
            {
                return OAC_V5_INVALID_VALUE;
            }
            ++index;
        }
        else if (value >= 0xdc00 && value <= 0xdfff)
        {
            return OAC_V5_INVALID_VALUE;
        }
    }

    if (Path[PathLength - 1] == L'.' || Path[PathLength - 1] == L' ' ||
        (PathLength - componentStart == 1 &&
         Path[componentStart] == L'.') ||
        (PathLength - componentStart == 2 &&
         Path[componentStart] == L'.' &&
         Path[componentStart + 1] == L'.'))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OacV5ValidateReserved(
        &Path[PathLength],
        (OAC_LAUNCH_MAX_CANONICAL_NT_PATH_CHARS - PathLength) * sizeof(WCHAR));
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

static __inline OAC_LAUNCH_DECISION OacDecideLaunchCandidate(
    OAC_V5_SESSION_STATE State,
    ULONGLONG CurrentTime100ns,
    ULONGLONG ExpirationInterruptTime100ns,
    BOOLEAN CreatorMatches,
    BOOLEAN NameAvailable,
    BOOLEAN PathMatches)
{
    if (!CreatorMatches)
    {
        return OAC_LAUNCH_IGNORE;
    }
    if (State == OAC_V5_SESSION_TARGET_BOUND ||
        State == OAC_V5_SESSION_MONITORING)
    {
        return OAC_LAUNCH_DENY_SERVICE_CREATION_AFTER_BIND;
    }
    if (State != OAC_V5_SESSION_LAUNCH_PENDING)
    {
        return OAC_LAUNCH_IGNORE;
    }
    if (CurrentTime100ns >= ExpirationInterruptTime100ns)
    {
        return OAC_LAUNCH_REVOKE_EXPIRED;
    }
    if (!NameAvailable || !PathMatches)
    {
        return OAC_LAUNCH_REVOKE_MISMATCH;
    }
    return OAC_LAUNCH_CONSUME_BIND;
}

static __inline BOOLEAN OacV5RevokeReasonValid(OAC_V5_REVOKE_REASON Reason)
{
    return Reason <= OAC_REVOKE_TARGET_CONFIRMATION_FAILED;
}

static __inline BOOLEAN OacSessionLossStateValid(
    ULONGLONG Sequence,
    OAC_V5_REVOKE_REASON Reason)
{
    return OacV5RevokeReasonValid(Reason) &&
        ((Sequence == 0) == (Reason == OAC_V5_REVOKE_NONE));
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

static __inline BOOLEAN OacEvidenceChannelValid(ULONG Channel)
{
    return Channel == OAC_EVIDENCE_CHANNEL_ALERT ||
        Channel == OAC_EVIDENCE_CHANNEL_EVENT;
}

static __inline BOOLEAN OacEventBelongsToEvidenceChannel(
    const OAC_V5_EVENT_RECORD* Record,
    ULONG Channel)
{
    BOOLEAN alert;

    if (Record == NULL || !OacEvidenceChannelValid(Channel)) return FALSE;
    alert = Record->ObservationSeverity >= OAC_V5_OBSERVATION_HIGH ||
        Record->PolicySeverity >= OAC_V5_POLICY_HIGH;
    return Channel == OAC_EVIDENCE_CHANNEL_ALERT ? alert : !alert;
}

static __inline BOOLEAN OacSnapshotOperationValid(ULONG Operation)
{
    return Operation >= OAC_SNAPSHOT_OPERATION_OPEN &&
        Operation <= OAC_SNAPSHOT_OPERATION_CLOSE;
}

static __inline BOOLEAN OacSnapshotTypeValid(ULONG SnapshotType)
{
    return SnapshotType == OAC_SNAPSHOT_TYPE_KERNEL_MODULES;
}

static __inline BOOLEAN OacSnapshotStateValid(ULONG State)
{
    return State >= OAC_SNAPSHOT_STATE_READY &&
        State <= OAC_SNAPSHOT_STATE_CLOSED;
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

static __inline OAC_V5_VALIDATION OacValidateEvidenceReadRequest(
    const OAC_EVIDENCE_READ_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSessionRequest(
        &Request->Header,
        InputLength,
        sizeof(*Request),
        OAC_MESSAGE_READ_EVIDENCE,
        0);
    if (result != OAC_V5_VALID) return result;
    if (!OacEvidenceChannelValid(Request->Channel) ||
        Request->MaximumRecords == 0 ||
        Request->MaximumRecords > OAC_EVIDENCE_MAX_RECORDS_PER_PAGE ||
        Request->AcknowledgeThrough > Request->AfterSequence)
    {
        return OAC_V5_INVALID_VALUE;
    }
    if (Request->Channel == OAC_EVIDENCE_CHANNEL_EVENT &&
        Request->AcknowledgeThrough != 0)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return Request->Reserved == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_RESERVED;
}

static __inline OAC_V5_VALIDATION OacValidateEvidenceReadResponse(
    const OAC_EVIDENCE_READ_RESPONSE* Response,
    ULONG OutputLength)
{
    const ULONG prefix = FIELD_OFFSET(OAC_EVIDENCE_READ_RESPONSE, Records);
    ULONG expectedLength;
    ULONG index;
    ULONGLONG previous = 0;
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    if (Response->RecordCount > OAC_EVIDENCE_MAX_RECORDS_PER_PAGE ||
        Response->RecordCount > (OAC_V5_ULONG_MAX - prefix) /
            sizeof(OAC_V5_EVENT_RECORD))
    {
        return OAC_V5_INVALID_RANGE;
    }
    expectedLength = prefix +
        Response->RecordCount * sizeof(OAC_V5_EVENT_RECORD);
    result = OacV5ValidateResponseHeader(
        &Response->Header,
        OutputLength,
        expectedLength,
        OAC_MESSAGE_READ_EVIDENCE,
        OAC_V5_RESPONSE_MORE_DATA | OAC_V5_RESPONSE_PARTIAL |
            OAC_V5_RESPONSE_REVOKED,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (!OacEvidenceChannelValid(Response->Channel) ||
        Response->Reserved != 0 || Response->LossLatched > 1 ||
        Response->AcknowledgedSequence > Response->PublishedSequence ||
        ((Response->FirstAvailableSequence == 0) !=
         (Response->LastAvailableSequence == 0)) ||
        (Response->FirstAvailableSequence != 0 &&
         (Response->FirstAvailableSequence > Response->LastAvailableSequence ||
          Response->LastAvailableSequence > Response->PublishedSequence)) ||
        ((Response->LossLatched == 0) !=
         (Response->FirstLostSequence == 0)))
    {
        return OAC_V5_INVALID_VALUE;
    }
    if (Response->Channel == OAC_EVIDENCE_CHANNEL_ALERT)
    {
        if (Response->DroppedCount < Response->LostHighCount ||
            Response->DroppedCount - Response->LostHighCount !=
                Response->LostCriticalCount ||
            (Response->FirstAvailableSequence != 0 &&
             Response->FirstAvailableSequence <=
                Response->AcknowledgedSequence))
        {
            return OAC_V5_INVALID_VALUE;
        }
    }
    else if (Response->AcknowledgedSequence != 0 ||
        Response->LostHighCount != 0 ||
        Response->LostCriticalCount != 0)
    {
        return OAC_V5_INVALID_VALUE;
    }
    if ((Response->LossLatched == 0 && Response->DroppedCount != 0) ||
        (Response->LossLatched != 0 &&
         (Response->DroppedCount == 0 ||
          Response->FirstLostSequence > Response->PublishedSequence)))
    {
        return OAC_V5_INVALID_VALUE;
    }

    for (index = 0; index < Response->RecordCount; ++index)
    {
        const OAC_V5_EVENT_RECORD* record = &Response->Records[index];

        result = OacV5ValidateEventRecord(record, sizeof(*record));
        if (result != OAC_V5_VALID) return result;
        if (!OacV5SessionIdEqual(
                &record->SessionId,
                &Response->Header.SessionId) ||
            record->Generation != Response->Header.Generation ||
            !OacEventBelongsToEvidenceChannel(record, Response->Channel) ||
            record->Sequence <= previous ||
            record->Sequence < Response->FirstAvailableSequence ||
            record->Sequence > Response->LastAvailableSequence)
        {
            return OAC_V5_INVALID_VALUE;
        }
        previous = record->Sequence;
    }
    if (((Response->Header.Flags & OAC_V5_RESPONSE_MORE_DATA) != 0) !=
        (Response->RecordCount != 0 &&
         previous < Response->LastAvailableSequence))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacValidateSnapshotRecord(
    const OAC_SNAPSHOT_RECORD* Record,
    ULONG RecordLength)
{
    ULONG index;
    OAC_V5_VALIDATION result;

    if (Record == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSize(
        RecordLength,
        Record->Size,
        sizeof(*Record),
        sizeof(*Record));
    if (result != OAC_V5_VALID) return result;
    result = OacV5ValidateVersion(Record->Version);
    if (result != OAC_V5_VALID) return result;
    if (Record->RecordType != OAC_SNAPSHOT_RECORD_KERNEL_MODULE ||
        Record->Flags != OAC_SNAPSHOT_RECORD_FLAGS ||
        Record->Address == 0 || Record->Length == 0 ||
        Record->NameLength == 0 ||
        Record->NameLength >= OAC_SNAPSHOT_MAX_NAME_CHARS ||
        Record->Reserved != 0 ||
        Record->Name[Record->NameLength] != L'\0')
    {
        return OAC_V5_INVALID_VALUE;
    }
    for (index = 0; index < Record->NameLength; ++index)
    {
        USHORT value = (USHORT)Record->Name[index];
        if (value == 0 || value < 0x20 || value == 0x7f)
        {
            return OAC_V5_INVALID_VALUE;
        }
        if (value >= 0xd800 && value <= 0xdbff)
        {
            if (index + 1 >= Record->NameLength ||
                Record->Name[index + 1] < 0xdc00 ||
                Record->Name[index + 1] > 0xdfff)
            {
                return OAC_V5_INVALID_VALUE;
            }
            ++index;
        }
        else if (value >= 0xdc00 && value <= 0xdfff)
        {
            return OAC_V5_INVALID_VALUE;
        }
    }
    return OacV5ValidateReserved(
        &Record->Name[Record->NameLength + 1],
        (OAC_SNAPSHOT_MAX_NAME_CHARS - Record->NameLength - 1) *
            sizeof(WCHAR));
}

static __inline OAC_V5_VALIDATION OacValidateSnapshotRequest(
    const OAC_SNAPSHOT_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;
    BOOLEAN zeroId;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSessionRequest(
        &Request->Header,
        InputLength,
        sizeof(*Request),
        OAC_MESSAGE_MANAGE_SNAPSHOT,
        0);
    if (result != OAC_V5_VALID) return result;
    if (!OacSnapshotOperationValid(Request->Operation) ||
        !OacSnapshotTypeValid(Request->SnapshotType) ||
        Request->Reserved != 0)
    {
        return Request->Reserved != 0
            ? OAC_V5_INVALID_RESERVED
            : OAC_V5_INVALID_VALUE;
    }
    zeroId = OacSnapshotIdIsZero(&Request->SnapshotId);
    if (Request->Operation == OAC_SNAPSHOT_OPERATION_OPEN)
    {
        return zeroId && Request->CursorGeneration == 0 &&
            Request->Cursor == 0 && Request->MaximumRecords != 0 &&
            Request->MaximumRecords <= OAC_SNAPSHOT_MAX_RECORDS_PER_PAGE
            ? OAC_V5_VALID
            : OAC_V5_INVALID_VALUE;
    }
    if (zeroId || Request->CursorGeneration == 0)
    {
        return OAC_V5_INVALID_VALUE;
    }
    if (Request->Operation == OAC_SNAPSHOT_OPERATION_READ)
    {
        return Request->MaximumRecords != 0 &&
            Request->MaximumRecords <= OAC_SNAPSHOT_MAX_RECORDS_PER_PAGE
            ? OAC_V5_VALID
            : OAC_V5_INVALID_VALUE;
    }
    return Request->Cursor == 0 && Request->MaximumRecords == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_VALUE;
}

static __inline OAC_V5_VALIDATION OacValidateSnapshotResponse(
    const OAC_SNAPSHOT_RESPONSE* Response,
    ULONG OutputLength)
{
    const ULONG prefix = FIELD_OFFSET(OAC_SNAPSHOT_RESPONSE, Records);
    ULONG expectedLength;
    ULONG index;
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    if (Response->RecordCount > OAC_SNAPSHOT_MAX_RECORDS_PER_PAGE ||
        Response->RecordCount > (OAC_V5_ULONG_MAX - prefix) /
            sizeof(OAC_SNAPSHOT_RECORD))
    {
        return OAC_V5_INVALID_RANGE;
    }
    expectedLength = prefix +
        Response->RecordCount * sizeof(OAC_SNAPSHOT_RECORD);
    result = OacV5ValidateResponseHeader(
        &Response->Header,
        OutputLength,
        expectedLength,
        OAC_MESSAGE_MANAGE_SNAPSHOT,
        OAC_V5_RESPONSE_MORE_DATA | OAC_V5_RESPONSE_REVOKED,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (OacSnapshotIdIsZero(&Response->SnapshotId) ||
        !OacSnapshotTypeValid(Response->SnapshotType) ||
        !OacSnapshotStateValid(Response->State) ||
        Response->ScanId == 0 || Response->CreatedTimestamp100ns == 0 ||
        Response->ExpirationInterruptTime100ns == 0 ||
        Response->CursorGeneration == 0 || Response->Truncated > 1 ||
        Response->Reserved != 0 ||
        Response->AvailableItems > Response->TotalItems ||
        Response->Cursor > Response->AvailableItems ||
        Response->NextCursor < Response->Cursor ||
        Response->NextCursor > Response->AvailableItems ||
        Response->NextCursor - Response->Cursor != Response->RecordCount ||
        (Response->Truncated != 0) !=
            (Response->AvailableItems < Response->TotalItems))
    {
        return OAC_V5_INVALID_VALUE;
    }
    if (Response->State == OAC_SNAPSHOT_STATE_READY)
    {
        if (Response->FailureStatus != 0)
            return OAC_V5_INVALID_VALUE;
    }
    else if (Response->State == OAC_SNAPSHOT_STATE_FAILED)
    {
        if (Response->FailureStatus == 0 || Response->TotalItems != 0 ||
            Response->AvailableItems != 0 || Response->RecordCount != 0 ||
            Response->Cursor != 0 || Response->NextCursor != 0 ||
            Response->Truncated != 0)
        {
            return OAC_V5_INVALID_VALUE;
        }
    }
    else if (Response->FailureStatus != 0 || Response->RecordCount != 0 ||
        Response->Cursor != 0 || Response->NextCursor != 0)
    {
        return OAC_V5_INVALID_VALUE;
    }

    for (index = 0; index < Response->RecordCount; ++index)
    {
        result = OacValidateSnapshotRecord(
            &Response->Records[index],
            sizeof(Response->Records[index]));
        if (result != OAC_V5_VALID ||
            Response->Records[index].Index != Response->Cursor + index)
        {
            return OAC_V5_INVALID_VALUE;
        }
    }
    if (((Response->Header.Flags & OAC_V5_RESPONSE_MORE_DATA) != 0) !=
        (Response->State == OAC_SNAPSHOT_STATE_READY &&
         Response->NextCursor < Response->AvailableItems))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacValidateEvidenceReadCorrelation(
    const OAC_EVIDENCE_READ_REQUEST* Request,
    const OAC_EVIDENCE_READ_RESPONSE* Response)
{
    BOOLEAN partial;
    OAC_V5_VALIDATION result;

    if (Request == NULL || Response == NULL)
        return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateCorrelation(&Request->Header, &Response->Header);
    if (result != OAC_V5_VALID) return result;
    partial = Response->FirstAvailableSequence != 0 &&
        Request->AfterSequence < Response->FirstAvailableSequence - 1;
    if (Response->Channel != Request->Channel ||
        Response->RecordCount > Request->MaximumRecords ||
        Response->PublishedSequence < Request->AfterSequence ||
        Response->AcknowledgedSequence < Request->AcknowledgeThrough ||
        Response->AcknowledgedSequence > Request->AfterSequence ||
        (((Response->Header.Flags & OAC_V5_RESPONSE_PARTIAL) != 0) !=
            partial) ||
        (Response->RecordCount != 0 &&
         Response->Records[0].Sequence <= Request->AfterSequence) ||
        (Response->RecordCount == 0 &&
         Response->LastAvailableSequence > Request->AfterSequence))
    {
        return OAC_V5_INVALID_CORRELATION;
    }
    return OAC_V5_VALID;
}

static __inline OAC_V5_VALIDATION OacValidateSnapshotCorrelation(
    const OAC_SNAPSHOT_REQUEST* Request,
    const OAC_SNAPSHOT_RESPONSE* Response)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL || Response == NULL)
        return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateCorrelation(&Request->Header, &Response->Header);
    if (result != OAC_V5_VALID) return result;
    if (Response->SnapshotType != Request->SnapshotType ||
        Response->RecordCount > Request->MaximumRecords ||
        (Request->Operation != OAC_SNAPSHOT_OPERATION_OPEN &&
         (!OacSnapshotIdEqual(
              &Request->SnapshotId,
              &Response->SnapshotId) ||
          Request->CursorGeneration != Response->CursorGeneration)) ||
        (Request->Operation != OAC_SNAPSHOT_OPERATION_CLOSE &&
         Request->Cursor != Response->Cursor) ||
        (Request->Operation == OAC_SNAPSHOT_OPERATION_CLOSE &&
         Response->State != OAC_SNAPSHOT_STATE_CLOSED))
    {
        return OAC_V5_INVALID_CORRELATION;
    }
    return OAC_V5_VALID;
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
    if ((Request->Mode == OAC_V5_SESSION_PRODUCTION) !=
        !OacV5BufferIsZero(
            Request->BackendBindingSha256,
            sizeof(Request->BackendBindingSha256)))
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

static __inline OAC_V5_VALIDATION OacValidateRevokeSessionRequest(
    const OAC_REVOKE_SESSION_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSessionRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_V5_MESSAGE_REVOKE_SESSION, 0);
    if (result != OAC_V5_VALID) return result;
    if (Request->Reserved != 0) return OAC_V5_INVALID_RESERVED;
    return Request->RevokeReason == OAC_V5_REVOKE_REQUESTED
        ? OAC_V5_VALID
        : OAC_V5_INVALID_VALUE;
}

static __inline OAC_V5_VALIDATION OacValidateArmLaunchRequest(
    const OAC_ARM_LAUNCH_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSessionRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_MESSAGE_ARM_LAUNCH, 0);
    if (result != OAC_V5_VALID) return result;
    if (Request->TimeToLiveMilliseconds < OAC_LAUNCH_MIN_TTL_MS ||
        Request->TimeToLiveMilliseconds > OAC_LAUNCH_MAX_TTL_MS)
    {
        return OAC_V5_INVALID_RANGE;
    }
    if (Request->Reserved != 0) return OAC_V5_INVALID_RESERVED;
    if (OacV5BufferIsZero(
            Request->ManifestSha256,
            sizeof(Request->ManifestSha256)))
    {
        return OAC_V5_INVALID_VALUE;
    }
    result = OacValidateCanonicalNtPath(
        Request->CanonicalNtPath,
        Request->CanonicalNtPathLength);
    if (result != OAC_V5_VALID) return result;
    return OacValidateCanonicalDosDevicePath(
        Request->CanonicalDosDevicePath,
        Request->CanonicalDosDevicePathLength);
}

static __inline OAC_V5_VALIDATION OacValidateCancelLaunchRequest(
    const OAC_CANCEL_LAUNCH_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSessionRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_MESSAGE_CANCEL_LAUNCH, 0);
    if (result != OAC_V5_VALID) return result;
    return OacValidateLaunchId(&Request->LaunchId);
}

static __inline OAC_V5_VALIDATION OacValidateConfirmTargetRequest(
    const OAC_CONFIRM_TARGET_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSessionRequest(&Request->Header, InputLength,
        sizeof(*Request), OAC_MESSAGE_CONFIRM_TARGET, 0);
    if (result != OAC_V5_VALID) return result;
    result = OacValidateLaunchId(&Request->LaunchId);
    if (result != OAC_V5_VALID) return result;
    return Request->TargetProcessHandle != 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_VALUE;
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
        (((Response->Capabilities & OAC_V5_CAP_LAUNCH_TICKET) != 0) &&
         Response->MaximumInputSize < sizeof(OAC_ARM_LAUNCH_REQUEST)) ||
        Response->MaximumInputSize > OAC_V5_MAX_INPUT_SIZE ||
        Response->MaximumOutputSize < sizeof(OAC_V5_STATUS_RESPONSE) ||
        Response->MaximumOutputSize > OAC_V5_MAX_OUTPUT_SIZE ||
        Response->MaximumEventCount == 0 ||
        Response->MaximumEventCount > OAC_EVIDENCE_MAX_RECORDS_PER_PAGE)
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

static __inline OAC_V5_VALIDATION OacValidateArmLaunchResponse(
    const OAC_ARM_LAUNCH_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_MESSAGE_ARM_LAUNCH, 0,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    result = OacValidateLaunchId(&Response->LaunchId);
    if (result != OAC_V5_VALID) return result;
    if (Response->ExpirationInterruptTime100ns == 0 ||
        Response->State != OAC_V5_SESSION_LAUNCH_PENDING)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return Response->Reserved == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_RESERVED;
}

static __inline OAC_V5_VALIDATION OacValidateCancelLaunchResponse(
    const OAC_CANCEL_LAUNCH_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_MESSAGE_CANCEL_LAUNCH,
        OAC_V5_RESPONSE_REVOKED, OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (Response->Header.Flags != OAC_V5_RESPONSE_REVOKED ||
        Response->State != OAC_V5_SESSION_REVOKED)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return Response->Reserved == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_RESERVED;
}

static __inline OAC_V5_VALIDATION OacValidateConfirmTargetResponse(
    const OAC_CONFIRM_TARGET_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_MESSAGE_CONFIRM_TARGET, 0,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (Response->TargetProcessId == 0 ||
        Response->State != OAC_V5_SESSION_MONITORING)
    {
        return OAC_V5_INVALID_VALUE;
    }
    return Response->Reserved == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_RESERVED;
}

static __inline OAC_V5_VALIDATION OacValidateRevokeSessionResponse(
    const OAC_REVOKE_SESSION_RESPONSE* Response,
    ULONG OutputLength)
{
    OAC_V5_VALIDATION result;

    if (Response == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateResponseHeader(&Response->Header, OutputLength,
        sizeof(*Response), OAC_V5_MESSAGE_REVOKE_SESSION,
        OAC_V5_RESPONSE_REVOKED, OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (Response->Header.Flags != OAC_V5_RESPONSE_REVOKED ||
        Response->State != OAC_V5_SESSION_REVOKED ||
        Response->RevokeReason == OAC_V5_REVOKE_NONE ||
        !OacV5RevokeReasonValid(Response->RevokeReason) ||
        !OacSessionLossStateValid(
            Response->SessionLossSequence,
            Response->LastSessionLossReason))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return Response->Reserved == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_RESERVED;
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
        Response->EventsDropped > Response->EventsWritten ||
        !OacSessionLossStateValid(
            Response->SessionLossSequence,
            Response->LastSessionLossReason) ||
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
    if (((Response->State == OAC_V5_SESSION_CLAIMED ||
          Response->State == OAC_V5_SESSION_LAUNCH_PENDING) &&
         Response->TargetProcessId != 0) ||
        ((Response->State == OAC_V5_SESSION_TARGET_BOUND ||
          Response->State == OAC_V5_SESSION_MONITORING) &&
         Response->TargetProcessId == 0))
    {
        return OAC_V5_INVALID_VALUE;
    }
    if ((Response->State == OAC_V5_SESSION_CLAIMED &&
         !OacV5BufferIsZero(
             Response->ManifestSha256,
             sizeof(Response->ManifestSha256))) ||
        ((Response->State == OAC_V5_SESSION_LAUNCH_PENDING ||
          Response->State == OAC_V5_SESSION_TARGET_BOUND ||
          Response->State == OAC_V5_SESSION_MONITORING) &&
         OacV5BufferIsZero(
             Response->ManifestSha256,
             sizeof(Response->ManifestSha256))))
    {
        return OAC_V5_INVALID_VALUE;
    }
    if ((Response->SessionMode != OAC_V5_SESSION_PRODUCTION &&
         Response->SessionMode != OAC_V5_SESSION_DIAGNOSTIC) ||
        ((Response->SessionMode == OAC_V5_SESSION_PRODUCTION) !=
         !OacV5BufferIsZero(
             Response->BackendBindingSha256,
             sizeof(Response->BackendBindingSha256))))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return OAC_V5_VALID;
}
