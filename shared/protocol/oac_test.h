#pragma once

/*
 * Lab-only driver test contract. The driver accepts this IOCTL only when
 * LabMode is enabled and the caller owns an authenticated diagnostic session.
 */

#include "oac_validate.h"

#define OAC_TEST_PROTOCOL_VERSION 0x00010000UL
#define OAC_TEST_MAX_INJECTED_RECORDS 10000UL
#define OAC_TEST_MESSAGE_INJECT_EVIDENCE 0x0000081FUL

#define IOCTL_OAC_TEST_INJECT_EVIDENCE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81F, METHOD_BUFFERED, OAC_V5_IOCTL_ACCESS)

typedef struct OAC_TEST_INJECT_EVIDENCE_REQUEST_TAG
{
    OAC_V5_REQUEST_HEADER Header;
    ULONG TestVersion;
    ULONG Count;
    OAC_V5_RULE_ID RuleId;
    OAC_V5_EVENT_TYPE EventType;
    OAC_V5_OBSERVATION_SEVERITY ObservationSeverity;
    OAC_V5_POLICY_SEVERITY PolicySeverity;
    OAC_V5_CONFIDENCE Confidence;
    OAC_V5_CATEGORY Category;
    ULONGLONG EvidenceFlags;
    ULONGLONG Reserved;
} OAC_TEST_INJECT_EVIDENCE_REQUEST,
    *POAC_TEST_INJECT_EVIDENCE_REQUEST;

static __inline OAC_V5_VALIDATION OacValidateTestEvidenceRequest(
    const OAC_TEST_INJECT_EVIDENCE_REQUEST* Request,
    ULONG InputLength)
{
    OAC_V5_VALIDATION result;

    if (Request == NULL) return OAC_V5_INVALID_POINTER;
    result = OacV5ValidateSize(
        InputLength,
        Request->Header.Size,
        sizeof(*Request),
        sizeof(*Request));
    if (result != OAC_V5_VALID) return result;
    if (Request->Header.Version != OAC_V5_VERSION ||
        Request->Header.RequestId == 0 ||
        Request->Header.Flags != 0 ||
        Request->Header.MessageType != OAC_TEST_MESSAGE_INJECT_EVIDENCE)
    {
        return OAC_V5_INVALID_VALUE;
    }
    result = OacV5ValidateSession(
        &Request->Header.SessionId,
        Request->Header.Generation,
        OAC_V5_ID_REQUIRED);
    if (result != OAC_V5_VALID) return result;
    if (Request->TestVersion != OAC_TEST_PROTOCOL_VERSION ||
        Request->Count == 0 ||
        Request->Count > OAC_TEST_MAX_INJECTED_RECORDS ||
        !OacV5RuleIdValid(Request->RuleId) ||
        !OacV5EventTypeValid(Request->EventType) ||
        !OacV5ObservationSeverityValid(Request->ObservationSeverity) ||
        !OacV5PolicySeverityValid(Request->PolicySeverity) ||
        !OacV5ConfidenceValid(Request->Confidence) ||
        !OacV5CategoryValid(Request->Category) ||
        (Request->EvidenceFlags & ~OAC_V5_EVIDENCE_FLAGS) != 0 ||
        (Request->EventType == OAC_V5_EVENT_POLICY_VIOLATION &&
         Request->PolicySeverity == OAC_V5_POLICY_NOT_EVALUATED))
    {
        return OAC_V5_INVALID_VALUE;
    }
    return Request->Reserved == 0
        ? OAC_V5_VALID
        : OAC_V5_INVALID_RESERVED;
}

#ifdef __cplusplus
#define OAC_TEST_STATIC_ASSERT(Expression, Message) \
    static_assert((Expression), Message)
#elif defined(_KERNEL_MODE)
#define OAC_TEST_STATIC_ASSERT(Expression, Message) C_ASSERT(Expression)
#else
#define OAC_TEST_STATIC_ASSERT(Expression, Message) \
    _Static_assert((Expression), Message)
#endif

OAC_TEST_STATIC_ASSERT(
    ((IOCTL_OAC_TEST_INJECT_EVIDENCE >> 2) & 0xFFFUL) ==
        OAC_TEST_MESSAGE_INJECT_EVIDENCE,
    "test evidence message ID drifted");
OAC_TEST_STATIC_ASSERT(sizeof(OAC_TEST_INJECT_EVIDENCE_REQUEST) == 96,
    "OAC_TEST_INJECT_EVIDENCE_REQUEST layout changed");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    Header) == 0, "test request header moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    TestVersion) == 48, "test protocol version moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    Count) == 52, "test record count moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    RuleId) == 56, "test rule ID moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    EventType) == 60, "test event type moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    ObservationSeverity) == 64, "test severity moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    PolicySeverity) == 68, "test policy severity moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    Confidence) == 72, "test confidence moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    Category) == 76, "test category moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    EvidenceFlags) == 80, "test evidence flags moved");
OAC_TEST_STATIC_ASSERT(FIELD_OFFSET(OAC_TEST_INJECT_EVIDENCE_REQUEST,
    Reserved) == 88, "test reserved field moved");

#undef OAC_TEST_STATIC_ASSERT
