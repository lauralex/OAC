#pragma once

#include <Windows.h>

#include <array>
#include <string>
#include <vector>

#include "..\shared\oac_signed_policy.h"

namespace oac
{
struct VerifiedSignedRecord
{
    std::vector<unsigned char> Bytes;
    std::array<unsigned char, OAC_POLICY_HASH_SIZE> Digest{};
    std::array<unsigned char, OAC_POLICY_HASH_SIZE> SignerDigest{};
    std::vector<unsigned char> SignerCertificate;
};

DWORD VerifySignedRecord(
    const std::wstring& recordPath,
    const std::wstring& signaturePath,
    DWORD exactRecordSize,
    const wchar_t* signerRegistryValue,
    VerifiedSignedRecord& verified);

ULONGLONG CurrentUnixSeconds() noexcept;
std::wstring HexIdentity(const unsigned char* bytes, size_t count);
}
