#pragma once

#include "scanner.hpp"

#include <span>
#include <string>
#include <string_view>

namespace oac::client
{
bool ParseOptions(
    std::span<const std::wstring_view> arguments,
    ScanOptions& options);

bool ParsePositiveDword(std::wstring_view text, DWORD& value) noexcept;

std::wstring DeploymentModeName(DeploymentMode mode);
}
