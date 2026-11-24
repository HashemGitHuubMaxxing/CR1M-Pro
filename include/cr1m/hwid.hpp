// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include <cstdint>
#include <string>

namespace cr1m {

struct SmbiosSnapshot {
    int chassisType = -1;
    std::string sysMfr;
    std::string sysProd;
    std::string sysSerial;
    std::string boardMfr;
    std::string boardProd;
    std::string boardSerial;
    std::string uuidHex;
    bool uuidAllZero = false;
    bool uuidAllFF = false;
    bool uuidMalformed = false;
};

struct SpoofReport {
    bool regVsSmbiosMismatch = false;
    bool badSmbiosUuid = false;
    bool unexpectedHypervisor = false;
    bool dummyDiskSerial = false;
    bool boardBaselineDrift = false;
    bool diskBaselineDrift = false;
    bool osGuidDrift = false;
    std::string hvVendor;

    bool hasTrialBlockFlag() const;
    bool hasPurchaseWarning() const;
    std::string summaryEn() const;
    std::string summaryRu() const;
};

struct HwidBundle {
    std::string v1;
    std::string v2;
    std::string physTrialId;
    SpoofReport spoof;
};

SmbiosSnapshot ReadSmbiosSnapshot();
HwidBundle     ComputeHwidBundle();
void           PrintSpooferWarning(const SpoofReport& sp);
bool           ConfirmSpooferBeforeBind(const HwidBundle& hb, bool nonInteractive);

} // namespace cr1m
