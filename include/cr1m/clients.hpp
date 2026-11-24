// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include "cr1m/config.hpp"
#include <string>

namespace cr1m {

struct ClientInventory {
    bool hasMs = false;
    std::wstring steamExe;
    std::wstring wgcExe;
    DWORD pidMs = 0;
    DWORD pidSteam = 0;
    DWORD pidWgc = 0;

    int availableCount() const {
        return (hasMs ? 1 : 0) +
               ((!steamExe.empty() || pidSteam) ? 1 : 0) +
               ((!wgcExe.empty() || pidWgc) ? 1 : 0);
    }
};

DWORD           FindWotbPid(const std::string& storeFilter = "AUTO", DWORD ignorePid = 0);
ClientInventory DiscoverClients();
bool            LaunchSpecificStore(const std::string& store, const ClientInventory& inv);
std::string     SelectTargetClient(const ModConfig& cfg, const ClientInventory& inv, bool nonInteractive);
void            TerminateAndRelaunchSteam(DWORD oldPid, HANDLE& hProc, const ClientInventory& inv);

} // namespace cr1m
