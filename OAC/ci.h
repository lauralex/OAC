/**
 * @file ci.h
 * @brief Provides an interface for the Code Integrity (CI) subsystem.
 *
 * This module encapsulates all interactions with the undocumented CI.dll,
 * including function resolution and signature verification. All functions
 * in this module must be called at IRQL = PASSIVE_LEVEL.
 */
#pragma once
#include <ntddk.h>
#include "internals.h"

//
// === Undocumented Code Integrity Structures ===
// (As provided from public research)
//
typedef struct _WIN_CERTIFICATE
{
    ULONG  Length;
    USHORT Revision;
    USHORT CertificateType;
    UCHAR  Certificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, *PWIN_CERTIFICATE;

typedef struct _ASN1_BLOB_PTR
{
    int   Size;
    PVOID PtrToData;
} ASN1_BLOB_PTR, *PASN1_BLOB_PTR;

typedef struct _CERTIFICATE_PARTY_NAME
{
    PVOID PointerToName;
    short NameLen;
    short Unknown;
} CERTIFICATE_PARTY_NAME, *PCERTIFICATE_PARTY_NAME;

typedef struct _CERT_CHAIN_MEMBER
{
    int                    DigestIdetifier;
    int                    DigestSize;
    UCHAR                  DigestBuffer[64];
    CERTIFICATE_PARTY_NAME SubjectName;
    CERTIFICATE_PARTY_NAME IssuerName;
    ASN1_BLOB_PTR          Certificate;
} CERT_CHAIN_MEMBER, *PCERT_CHAIN_MEMBER;

typedef struct _CERT_CHAIN_INFO_HEADER
{
    int                BufferSize;
    PASN1_BLOB_PTR     PtrToPublicKeys;
    int                NumberOfPublicKeys;
    PASN1_BLOB_PTR     PtrToEkus;
    int                NumberOfEkus;
    PCERT_CHAIN_MEMBER PtrToCertChainMembers;
    int                NumberOfCertChainMembers;
    int                Unknown;
    ASN1_BLOB_PTR      VariousAuthenticodeAttributes;
} CERT_CHAIN_INFO_HEADER, *PCERT_CHAIN_INFO_HEADER;

typedef struct _POLICY_INFO
{
    int                     StructSize;
    NTSTATUS                VerificationStatus;
    int                     Flags;
    PCERT_CHAIN_INFO_HEADER CertChainInfo;
    FILETIME                RevocationTime;
    FILETIME                NotBeforeTime;
    FILETIME                NotAfterTime;
} POLICY_INFO, *PPOLICY_INFO;

//
// === Undocumented CI Function Prototypes ===
//
typedef NTSTATUS (NTAPI*CI_VALIDATE_FILE_OBJECT)(
    _In_ struct _FILE_OBJECT*              FileObject,
    _In_ int                               A2,
    _In_ int                               A3,
    _Out_ POLICY_INFO*                     PolicyInfoForSigner,
    _Out_ POLICY_INFO*                     PolicyInfoForTimestampingAuthority,
    _Out_ LARGE_INTEGER*                   SigningTime,
    _Out_writes_bytes_(*digestSize) UCHAR* DigestBuffer,
    _Inout_ int*                           DigestSize,
    _Out_ int*                             DigestIdentifier
);

typedef PVOID (NTAPI*CI_FREE_POLICY_INFO)(
    _Inout_ POLICY_INFO* PolicyInfo
);


//
// === Public Function Prototypes ===
//

/**
 * @brief Dynamically resolves the addresses of necessary functions from ci.dll.
 * @return STATUS_SUCCESS if all required functions were found, otherwise an error status.
 * @note Must be called at PASSIVE_LEVEL during driver initialization.
 */
NTSTATUS ResolveCiFunctions(VOID);

/**
 * @brief Verifies the digital signature of the module containing a given RIP.
 * @param[in] Rip An instruction pointer within the module to be checked.
 * @return The NTSTATUS code from the verification check. STATUS_SUCCESS indicates a valid signature.
 * @note Must be called at PASSIVE_LEVEL.
 */
NTSTATUS VerifyModuleSignatureByRip(
    _In_ PVOID Rip
);
