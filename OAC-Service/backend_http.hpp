#pragma once

#include <Windows.h>

#include <memory>

namespace oac
{
class BackendTransport;

std::unique_ptr<BackendTransport> CreateHttpBackendTransport(
    DWORD& error) noexcept;
}
