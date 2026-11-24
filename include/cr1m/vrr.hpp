// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/auth_proof.hpp"
#include "cr1m/build_config.hpp"
#include "cr1m/config.hpp"
#include <cstdint>
#include <string>

namespace cr1m {

struct VrrAuditResult {
    bool hasNvidiaGpu = false;
    bool hasAmdGpu = false;
    bool isLaptop = false;
    bool isHybridIgpuDisplay = false;
    bool isMuxDirect = false;
    bool dxgiAllowTearing = false;
    bool winVrrRegEnabled = false;
    bool adlxChecked = false;
    bool adlxFreeSyncSupported = false;
    bool adlxFreeSyncEnabled = false;
    bool nvDrsChecked = false;
    uint32_t nvVrrMode = 0; // 0=disabled, 1=FS, 2=FS+Win
    bool needsPrompt = false;
    std::string gpuSummary;
    std::string topologySummary;
};

int            DetectMaxMonitorHz();
int            ComputeSafeTargetFps(const ModConfig& cfg, int monitorHz);
bool           EnsureExeGpuPreferences(const std::wstring& exePath);
VrrAuditResult RunVrrPreflight(const ModConfig& cfg, bool nonInteractive, const AuthProof& proof);

} // namespace cr1m
