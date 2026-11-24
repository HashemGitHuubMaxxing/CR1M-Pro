// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include <string>

namespace cr1m {

struct ModConfig {
    int targetFpsOverride = 0;     // 0 = AUTO
    std::string store     = "AUTO"; // AUTO | MSSTORE | STEAM | WGC
    std::string autoVrr   = "ASK";  // ASK | YES | NO
    std::string language  = "AUTO"; // AUTO | EN | RU
};

std::string GetExeDirA();
ModConfig   LoadConfig();

} // namespace cr1m
