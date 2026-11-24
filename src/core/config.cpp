// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/config.hpp"
#include "cr1m/util.hpp"
#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <vector>

namespace cr1m {

std::string GetExeDirA() {
    std::vector<wchar_t> buf(32768, L'\0');
    DWORD n = GetModuleFileNameW(NULL, buf.data(), static_cast<DWORD>(buf.size()));
    if (!n || n >= buf.size()) return ".";
    std::string s = WideToUtf8(std::wstring(buf.data(), n));
    size_t pos = s.find_last_of("\\/");
    return (pos == std::string::npos) ? "." : s.substr(0, pos);
}

ModConfig LoadConfig() {
    ModConfig cfg;
    std::string candidates[3] = {
        GetExeDirA() + "\\config.txt",
        "config.txt",
        GetAppDataBaseDir() + "\\config.txt"
    };
    for (const auto& p : candidates) {
        std::string text;
        if (!ReadFileUtf8W(Utf8ToWide(p), text)) continue;
        std::istringstream ifs(text);
        std::string line;
        while (std::getline(ifs, line)) {
            size_t hash = line.find('#');
            if (hash != std::string::npos) line = line.substr(0, hash);
            size_t semi = line.find(';');
            if (semi != std::string::npos) line = line.substr(0, semi);
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string k = ToUpperAscii(Trim(line.substr(0, eq)));
            std::string v = Trim(line.substr(eq + 1));
            std::string vu = ToUpperAscii(v);
            if (k == "TARGETFPS" || k == "TARGET_FPS") {
                if (vu != "AUTO" && !vu.empty()) {
                    int val = std::atoi(v.c_str());
                    if (val >= 30) cfg.targetFpsOverride = std::min(val, 154);
                }
            } else if (k == "STORE") {
                if (vu == "AUTO" || vu == "MSSTORE" || vu == "STEAM" || vu == "WGC") cfg.store = vu;
            } else if (k == "AUTOENABLEVRR" || k == "AUTO_VRR") {
                if (vu == "ASK" || vu == "YES" || vu == "NO") cfg.autoVrr = vu;
            } else if (k == "LANGUAGE" || k == "LANG") {
                if (vu == "AUTO" || vu == "EN" || vu == "RU") cfg.language = vu;
            }
        }
        break;
    }
    return cfg;
}

} // namespace cr1m
