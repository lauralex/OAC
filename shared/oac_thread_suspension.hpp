#pragma once

#include <Windows.h>

#include <cstdint>

namespace oac
{
class ScopedThreadSuspension final
{
public:
    explicit ScopedThreadSuspension(HANDLE thread) noexcept
        : thread_(thread)
    {
        if (thread_ == nullptr)
        {
            error_ = ERROR_INVALID_HANDLE;
            return;
        }
        if (SuspendThread(thread_) == MAXDWORD)
        {
            error_ = GetLastError();
            if (error_ == ERROR_SUCCESS) error_ = ERROR_GEN_FAILURE;
            return;
        }
        active_ = true;
        started100ns_ = CurrentTime100ns();
    }

    ~ScopedThreadSuspension()
    {
        if (active_) (void)ResumeThread(thread_);
    }

    ScopedThreadSuspension(const ScopedThreadSuspension&) = delete;
    ScopedThreadSuspension& operator=(const ScopedThreadSuspension&) = delete;

    [[nodiscard]] bool Active() const noexcept { return active_; }
    [[nodiscard]] DWORD Error() const noexcept { return error_; }
    [[nodiscard]] std::uint64_t Duration100ns() const noexcept
    {
        return duration100ns_;
    }

    DWORD Resume() noexcept
    {
        if (!active_) return error_;
        if (ResumeThread(thread_) == MAXDWORD)
        {
            error_ = GetLastError();
            if (error_ == ERROR_SUCCESS) error_ = ERROR_GEN_FAILURE;
            return error_;
        }
        const std::uint64_t ended100ns = CurrentTime100ns();
        duration100ns_ = ended100ns >= started100ns_
            ? ended100ns - started100ns_
            : 0;
        active_ = false;
        error_ = ERROR_SUCCESS;
        return ERROR_SUCCESS;
    }

private:
    static std::uint64_t CurrentTime100ns() noexcept
    {
        ULONGLONG value = 0;
        if (QueryUnbiasedInterruptTime(&value)) return value;
        return GetTickCount64() * 10000ULL;
    }

    HANDLE thread_ = nullptr;
    std::uint64_t started100ns_ = 0;
    std::uint64_t duration100ns_ = 0;
    DWORD error_ = ERROR_SUCCESS;
    bool active_ = false;
};
} // namespace oac
