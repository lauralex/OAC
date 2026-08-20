#pragma once

#include <Windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "..\shared\protocol\oac_v5.h"

namespace oac
{
struct EndpointObservation
{
    OAC_V5_RULE_ID RuleId = 0;
    OAC_V5_EVENT_TYPE EventType = OAC_V5_EVENT_OBSERVATION;
    OAC_V5_OBSERVATION_SEVERITY Severity = OAC_V5_OBSERVATION_INFO;
    OAC_V5_CATEGORY Category = OAC_V5_CATEGORY_GENERAL;
    OAC_V5_SCAN_ID ScanId = 0;
    ULONGLONG ProcessId = 0;
    ULONGLONG ThreadId = 0;
    ULONGLONG Address = 0;
    ULONGLONG Auxiliary = 0;
    ULONGLONG EvidenceFlags = 0;
    std::wstring Text;
};

struct EndpointPreflightResult
{
    OAC_ENDPOINT_SCAN_RESPONSE Scan{};
    OAC_V5_SCAN_ID ModuleSnapshotScanId = 0;
    ULONG ModulesInspected = 0;
    std::vector<EndpointObservation> Observations;
};

DWORD CollectEndpointPreflight(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation,
    EndpointPreflightResult& result) noexcept;

DWORD ConfigureEndpointMonitoring(
    HANDLE driver,
    const OAC_V5_SESSION_ID& sessionId,
    ULONGLONG generation) noexcept;
} // namespace oac
