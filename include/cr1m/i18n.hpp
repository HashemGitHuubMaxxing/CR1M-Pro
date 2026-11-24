// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include <string>

namespace cr1m {

enum class UiLang { EN = 0, RU = 1 };

UiLang GetUiLang();
void   SetUiLang(UiLang lang);
bool   IsRu();

inline std::string Tr(const char* en, const char* ru) {
    return IsRu() ? std::string(ru) : std::string(en);
}

#define TR(en, ru) ::cr1m::Tr(en, ru)

bool IsInteractiveStdout();
void ConPrint(const std::string& utf8);
void ConClearInteractiveScreen();

bool DetectRussianOsLocale();
void ResolveUiLanguage(const std::string& cfgLang,
                       const std::string& cliLang,
                       bool resetLang,
                       bool nonInteractive);

} // namespace cr1m
