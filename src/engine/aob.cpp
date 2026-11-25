// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/aob.hpp"
#include "cr1m/win_runtime.hpp"
#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace cr1m {

namespace {

bool IsHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool ParseSemverParts(const std::string& s, int& maj, int& minv, int& pat) {
    maj = minv = pat = 0;
    size_t d1 = s.find('.');
    if (d1 == std::string::npos || d1 == 0 || d1 > 3) return false;
    size_t d2 = s.find('.', d1 + 1);
    if (d2 == std::string::npos || d2 == d1 + 1 || d2 - d1 - 1 > 3) return false;
    size_t rem = s.size() - (d2 + 1);
    if (rem == 0 || rem > 3) return false;
    auto parseNum = [](const std::string& part, int& out) -> bool {
        for (char c : part) {
            if (c < '0' || c > '9') return false;
        }
        out = std::atoi(part.c_str());
        return true;
    };
    return parseNum(s.substr(0, d1), maj) &&
           parseNum(s.substr(d1 + 1, d2 - d1 - 1), minv) &&
           parseNum(s.substr(d2 + 1), pat);
}

bool ValidateRulePattern(const std::string& pat) {
    if (pat.size() < 8 || pat.size() > 240) return false;
    std::istringstream iss(pat);
    std::string tok;
    size_t tokenCount = 0;
    size_t fixedCount = 0;
    while (iss >> tok) {
        ++tokenCount;
        if (tokenCount > 80) return false;
        if (tok == "?" || tok == "??") {
            continue;
        }
        if (tok.size() == 2 && IsHexChar(tok[0]) && IsHexChar(tok[1])) {
            ++fixedCount;
            continue;
        }
        if (tok.size() == 5 && tok[2] == '|' &&
            IsHexChar(tok[0]) && IsHexChar(tok[1]) &&
            IsHexChar(tok[3]) && IsHexChar(tok[4])) {
            continue;
        }
        return false;
    }
    return tokenCount >= 4 && fixedCount >= 4;
}

bool HasDiv1000Prefix(const uint8_t* txt, size_t idx) {
    static constexpr uint8_t kDiv1000[7] = { 0xB8, 0xE8, 0x03, 0x00, 0x00, 0x99, 0xF7 };
    size_t start = (idx > 64) ? (idx - 64) : 0;
    if (idx < start + sizeof(kDiv1000)) return false;
    for (size_t p = start; p + sizeof(kDiv1000) <= idx; ++p) {
        if (memcmp(txt + p, kDiv1000, sizeof(kDiv1000)) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace

void ModSessionState::recordOriginal(uint32_t rva, const std::vector<uint8_t>& curBytes) {
    for (const auto& b : backups) {
        if (b.rva == rva) return;
    }
    backups.push_back({ rva, curBytes });
}

ScopedProcessFreeze::ScopedProcessFreeze(HANDLE hp) : hProc_(hp) {
    auto& api = runtime::Api();
    if (hProc_ && api.pNtSuspend && api.pNtResume) {
        if (api.pNtSuspend(hProc_) == 0) frozen_ = true;
    }
}

ScopedProcessFreeze::~ScopedProcessFreeze() {
    auto& api = runtime::Api();
    if (frozen_ && api.pNtResume) api.pNtResume(hProc_);
}

uintptr_t GetWotbModuleBase(DWORD pid) {
    HANDLE s = runtime::DynCreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    uintptr_t b = 0;
    if (runtime::DynModule32FirstW(s, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"wotblitz.exe") == 0) {
                b = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (runtime::DynModule32NextW(s, &me));
    }
    CloseHandle(s);
    return b;
}

std::vector<PatElem> ParseAobPattern(const char* s) {
    std::vector<PatElem> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        if (tok == "??" || tok == "?") {
            out.push_back({ -1, 0, 0 });
        } else {
            size_t bar = tok.find('|');
            if (bar != std::string::npos) {
                uint8_t x = static_cast<uint8_t>(strtoul(tok.substr(0, bar).c_str(), nullptr, 16));
                uint8_t y = static_cast<uint8_t>(strtoul(tok.substr(bar + 1).c_str(), nullptr, 16));
                out.push_back({ -2, x, y });
            } else {
                out.push_back({ static_cast<int16_t>(strtoul(tok.c_str(), nullptr, 16)), 0, 0 });
            }
        }
    }
    return out;
}

std::vector<uint32_t> ScanAobAll(const uint8_t* buf, size_t sz, uint32_t baseRva, const char* patStr) {
    auto pat = ParseAobPattern(patStr);
    std::vector<uint32_t> hits;
    if (pat.empty() || sz < pat.size()) return hits;

    size_t anchor = 0;
    bool hasFixedAnchor = false;
    for (size_t i = 0; i < pat.size(); ++i) {
        if (pat[i].b >= 0) {
            anchor = i;
            hasFixedAnchor = true;
            break;
        }
    }
    if (!hasFixedAnchor) return hits;

    uint8_t ancVal = static_cast<uint8_t>(pat[anchor].b);
    size_t limit = sz - pat.size();

    for (size_t i = 0; i <= limit; ) {
        const uint8_t* found = static_cast<const uint8_t*>(memchr(buf + i + anchor, ancVal, limit - i + 1));
        if (!found) break;
        size_t pos = static_cast<size_t>(found - buf) - anchor;
        bool ok = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (pat[j].b == -1) continue;
            uint8_t v = buf[pos + j];
            if (pat[j].b == -2) {
                if (v != pat[j].a1 && v != pat[j].a2) { ok = false; break; }
            } else if (v != static_cast<uint8_t>(pat[j].b)) {
                ok = false; break;
            }
        }
        if (ok) hits.push_back(baseRva + static_cast<uint32_t>(pos));
        i = pos + 1;
    }
    return hits;
}

uint32_t ScanAob(const uint8_t* buf, size_t sz, uint32_t baseRva, const std::string& patStr, int offset) {
    auto hits = ScanAobAll(buf, sz, baseRva, patStr.c_str());
    if (hits.size() != 1) return 0;
    int64_t resolved = static_cast<int64_t>(hits[0]) + static_cast<int64_t>(offset);
    if (resolved < static_cast<int64_t>(baseRva) || resolved >= static_cast<int64_t>(baseRva) + static_cast<int64_t>(sz)) {
        return 0;
    }
    return static_cast<uint32_t>(resolved);
}

bool ReadMem(HANDLE hp, uintptr_t addr, void* out, size_t len) {
    SIZE_T br = 0;
    return runtime::DynReadProcessMemory(hp, reinterpret_cast<LPCVOID>(addr), out, len, &br) && br == len;
}

bool PatchVerified(HANDLE hp, uintptr_t base, uint32_t rva, const void* data, size_t len, ModSessionState* sess) {
    std::vector<uint8_t> cur(len);
    if (!ReadMem(hp, base + rva, cur.data(), len)) {
        return false;
    }
    if (memcmp(cur.data(), data, len) == 0) {
        return true;
    }

    if (sess) sess->recordOriginal(rva, cur);

    DWORD oldProt = 0;
    if (!runtime::DynVirtualProtectEx(hp, reinterpret_cast<LPVOID>(base + rva), len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }
    SIZE_T bw = 0;
    BOOL wr = runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(base + rva), data, len, &bw);
    FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(base + rva), len);
    DWORD dummy = 0;
    runtime::DynVirtualProtectEx(hp, reinterpret_cast<LPVOID>(base + rva), len, oldProt, &dummy);

    std::vector<uint8_t> ver(len);
    return wr && bw == len && ReadMem(hp, base + rva, ver.data(), len) && memcmp(ver.data(), data, len) == 0;
}

Kernel32Iat ResolveKernel32Iat(HANDLE hp, uintptr_t base, bool is64, uint32_t impRva, uint32_t impSz) {
    Kernel32Iat res;
    for (uint32_t off = 0; off < impSz; off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR iid{};
        if (!ReadMem(hp, base + impRva + off, &iid, sizeof(iid)) || !iid.Name) break;
        char dll[64]{};
        ReadMem(hp, base + iid.Name, dll, 63);
        if (_stricmp(dll, "KERNEL32.dll") == 0) {
            uint32_t stride = is64 ? 8u : 4u;
            for (uint32_t idx = 0; ; ++idx) {
                uint64_t oft = 0;
                if (!ReadMem(hp, base + iid.OriginalFirstThunk + idx * stride, &oft, stride) || !oft) break;
                uint64_t ordFlag = is64 ? 0x8000000000000000ULL : 0x80000000ULL;
                if (!(oft & ordFlag)) {
                    char fn[64]{};
                    ReadMem(hp, base + static_cast<uint32_t>(oft) + 2, fn, 63);
                    if (strcmp(fn, "QueryPerformanceCounter") == 0) res.pQpcRva   = iid.FirstThunk + idx * stride;
                    else if (strcmp(fn, "Sleep") == 0)             res.pSleepRva = iid.FirstThunk + idx * stride;
                }
            }
            break;
        }
    }
    return res;
}

int CompareSemver(const std::string& a, const std::string& b) {
    int am = 0, an = 0, ap = 0;
    int bm = 0, bn = 0, bp = 0;
    if (!ParseSemverParts(a, am, an, ap) || !ParseSemverParts(b, bm, bn, bp)) return 0;
    if (am != bm) return (am < bm) ? -1 : 1;
    if (an != bn) return (an < bn) ? -1 : 1;
    if (ap != bp) return (ap < bp) ? -1 : 1;
    return 0;
}

bool IsValidSigSlotName(const std::string& slot, bool is64) {
    static const char* kShared[] = {
        "SwitchT", "LoopB", "GetFps", "SetFps", "Win10",
        "UpdRoundf", "UpdSnap1", "UpdRotSnap", "RotBr", "RotAcc",
        "SilVisDup", "SilAddDedup", "PrecacheCamo1", "PrecacheCamo2"
    };
    for (const char* s : kShared) {
        if (slot == s) return true;
    }
    if (!is64) {
        static const char* kX86Extra[] = { "UpdSnap2", "UpdSnap3", "SilAddTail" };
        for (const char* s : kX86Extra) {
            if (slot == s) return true;
        }
    }
    return false;
}

bool ParseSignedSigManifestPayload(const std::string& payload, bool expectedIs64, SignedSigManifest& out) {
    out = SignedSigManifest{};
    if (payload.empty() || payload.size() > 16384) return false;

    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= payload.size()) {
        size_t nl = payload.find('\n', start);
        if (nl == std::string::npos) {
            lines.push_back(payload.substr(start));
            break;
        }
        lines.push_back(payload.substr(start, nl - start));
        start = nl + 1;
    }
    if (lines.size() < 5) return false;
    if (lines[0] != "CR1M-SIGS-V1") return false;
    if (lines[1].rfind("v=", 0) != 0) return false;
    if (lines[2].rfind("arch=", 0) != 0) return false;
    if (lines[3].rfind("latest=", 0) != 0) return false;
    if (lines[4].rfind("issued=", 0) != 0) return false;

    std::string verStr = lines[1].substr(2);
    if (verStr.empty() || verStr.size() > 10) return false;
    for (char c : verStr) {
        if (c < '0' || c > '9') return false;
    }
    uint64_t parsedVer = strtoull(verStr.c_str(), nullptr, 10);
    if (parsedVer < 1 || parsedVer > UINT32_MAX) return false;

    std::string archStr = lines[2].substr(5);
    std::string expectedArch = expectedIs64 ? "x64" : "x86";
    if (archStr != expectedArch) return false;

    std::string latestStr = lines[3].substr(7);
    int maj = 0, minv = 0, pat = 0;
    if (!ParseSemverParts(latestStr, maj, minv, pat)) return false;

    std::string issuedStr = lines[4].substr(7);
    if (issuedStr.size() < 10 || issuedStr.size() > 64) return false;

    std::vector<SigRule> rules;
    for (size_t i = 5; i < lines.size(); ++i) {
        if (lines[i].empty()) return false;
        if (lines[i].rfind("rule=", 0) != 0) return false;
        if (rules.size() >= 32) return false;
        std::string body = lines[i].substr(5);
        size_t p1 = body.find('|');
        if (p1 == std::string::npos) return false;
        size_t p2 = body.find('|', p1 + 1);
        if (p2 == std::string::npos) return false;
        size_t p3 = body.find('|', p2 + 1);
        if (p3 == std::string::npos) return false;

        std::string slot = body.substr(0, p1);
        std::string mode = body.substr(p1 + 1, p2 - p1 - 1);
        std::string offStr = body.substr(p2 + 1, p3 - p2 - 1);
        std::string pattern = body.substr(p3 + 1);

        if (!IsValidSigSlotName(slot, expectedIs64)) return false;
        if (mode != "direct" && mode != "call") return false;
        if (offStr.empty() || offStr.size() > 5) return false;
        size_t idx = (offStr[0] == '-') ? 1u : 0u;
        if (idx >= offStr.size()) return false;
        for (; idx < offStr.size(); ++idx) {
            if (offStr[idx] < '0' || offStr[idx] > '9') return false;
        }
        long parsedOff = strtol(offStr.c_str(), nullptr, 10);
        if (parsedOff < -64 || parsedOff > 128) return false;
        if (!ValidateRulePattern(pattern)) return false;

        SigRule r;
        r.slot = slot;
        r.isCall = (mode == "call");
        r.offset = static_cast<int32_t>(parsedOff);
        r.pattern = pattern;
        rules.push_back(std::move(r));
    }

    out.version = static_cast<uint32_t>(parsedVer);
    out.arch = archStr;
    out.latestModVersion = latestStr;
    out.issuedAt = issuedStr;
    out.rules = std::move(rules);
    out.rawPayload = payload;
    return true;
}

uint32_t EvaluateManifestRulesForSlot(const uint8_t* txt, size_t txtSz, uint32_t txtRva,
                                      const SignedSigManifest& manifest, const std::string& slotName) {
    if (!txt || txtSz == 0) return 0;
    uint32_t resolved = 0;
    for (const auto& rule : manifest.rules) {
        if (rule.slot != slotName) continue;
        auto hits = ScanAobAll(txt, txtSz, txtRva, rule.pattern.c_str());
        if (hits.size() != 1) continue;

        int64_t site = static_cast<int64_t>(hits[0]) + static_cast<int64_t>(rule.offset);
        if (site < static_cast<int64_t>(txtRva) ||
            site >= static_cast<int64_t>(txtRva) + static_cast<int64_t>(txtSz)) {
            continue;
        }

        uint32_t cand = 0;
        if (!rule.isCall) {
            cand = static_cast<uint32_t>(site);
        } else {
            size_t relOff = static_cast<size_t>(site - static_cast<int64_t>(txtRva));
            if (relOff + 5 > txtSz || txt[relOff] != 0xE8) continue;
            int32_t rel32 = 0;
            memcpy(&rel32, txt + relOff + 1, 4);
            int64_t target = site + 5 + static_cast<int64_t>(rel32);
            if (target < static_cast<int64_t>(txtRva) ||
                target >= static_cast<int64_t>(txtRva) + static_cast<int64_t>(txtSz)) {
                continue;
            }
            cand = static_cast<uint32_t>(target);
        }

        if (cand != 0) {
            if (resolved != 0 && resolved != cand) {
                // Reject ambiguous conflicting multi rule resolutions on the same binary.
                return 0;
            }
            resolved = cand;
        }
    }
    return resolved;
}

uint32_t ResolveLoopBByIat(const uint8_t* txt, size_t txtSz, uint32_t txtRva,
                           uintptr_t baseAddr, bool is64, uint32_t sleepIatRva,
                           HANDLE hp, uint32_t caveMagic) {
    if (!txt || txtSz < 16 || !sleepIatRva) return 0;
    std::vector<uint32_t> matches;

    // Scan FF 15 indirect calls targeting KERNEL32!Sleep preceded within 64 bytes by 1000 / idiv.
    for (size_t i = 0; i + 6 <= txtSz; ++i) {
        if (txt[i] == 0xFF && txt[i + 1] == 0x15) {
            bool isSleep = false;
            if (is64) {
                int32_t disp = 0;
                memcpy(&disp, txt + i + 2, 4);
                int64_t target = static_cast<int64_t>(txtRva) + static_cast<int64_t>(i) + 6 + static_cast<int64_t>(disp);
                isSleep = (target == static_cast<int64_t>(sleepIatRva));
            } else {
                uint32_t absVa = 0;
                memcpy(&absVa, txt + i + 2, 4);
                uint32_t expectedVa = static_cast<uint32_t>(baseAddr) + sleepIatRva;
                isSleep = (absVa == expectedVa);
            }
            if (isSleep && HasDiv1000Prefix(txt, i)) {
                matches.push_back(txtRva + static_cast<uint32_t>(i));
            }
        }
    }

    // Also support re attach when LoopB was already hooked to an active CRM5 cave.
    if (matches.empty() && hp != NULL && caveMagic != 0) {
        for (size_t i = 0; i + 6 <= txtSz; ++i) {
            if (txt[i] == 0xE8 && txt[i + 5] == 0x90 && HasDiv1000Prefix(txt, i)) {
                int32_t rel = 0;
                memcpy(&rel, txt + i + 1, 4);
                uintptr_t cand = baseAddr + txtRva + i + 5 + static_cast<intptr_t>(rel);
                uint32_t mag = 0;
                if (cand >= 0x60 && ReadMem(hp, cand - 0x60, &mag, 4) && mag == caveMagic) {
                    matches.push_back(txtRva + static_cast<uint32_t>(i));
                }
            }
        }
    }

    return (matches.size() == 1) ? matches[0] : 0;
}

uint32_t ResolveGetFpsNearLoopB(const uint8_t* txt, size_t txtSz, uint32_t txtRva,
                                uintptr_t baseAddr, bool is64, uint32_t loopBRva) {
    if (!txt || txtSz < 32 || loopBRva < txtRva + 0x20) return 0;
    size_t loopOff = static_cast<size_t>(loopBRva - txtRva);
    if (loopOff >= txtSz) return 0;
    size_t scanStart = (loopOff > 0x600) ? (loopOff - 0x600) : 0;
    size_t scanEnd = (loopOff > 0x20) ? (loopOff - 0x20) : 0;

    uint32_t foundAny = 0;
    bool anyAmbiguous = false;
    uint32_t foundInc = 0;
    bool incAmbiguous = false;
    for (size_t i = scanStart; i + 5 <= scanEnd; ++i) {
        if (txt[i] != 0xE8) continue;
        int32_t rel = 0;
        memcpy(&rel, txt + i + 1, 4);
        int64_t targetRva = static_cast<int64_t>(txtRva) + static_cast<int64_t>(i) + 5 + static_cast<int64_t>(rel);
        if (targetRva < static_cast<int64_t>(txtRva) ||
            targetRva + 7 > static_cast<int64_t>(txtRva) + static_cast<int64_t>(txtSz)) {
            continue;
        }
        size_t tOff = static_cast<size_t>(targetRva - static_cast<int64_t>(txtRva));
        bool looksLikeGetFps = false;
        if (is64) {
            bool stock = (txt[tOff] == 0x8B && txt[tOff + 1] == 0x05 && txt[tOff + 6] == 0xC3);
            bool patched = (txt[tOff] == 0xB8 && txt[tOff + 5] == 0xC3 && txt[tOff + 6] == 0x90);
            looksLikeGetFps = (stock || patched);
        } else {
            bool stock = false;
            if (txt[tOff] == 0xA1 && txt[tOff + 5] == 0xC3) {
                uint32_t va = 0;
                memcpy(&va, txt + tOff + 1, 4);
                stock = (va > static_cast<uint32_t>(baseAddr) && va < static_cast<uint32_t>(baseAddr) + 0x10000000u);
            }
            bool patched = (txt[tOff] == 0xB8 && txt[tOff + 5] == 0xC3);
            looksLikeGetFps = (stock || patched);
        }
        if (looksLikeGetFps) {
            uint32_t r = static_cast<uint32_t>(targetRva);
            if (foundAny != 0 && foundAny != r) anyAmbiguous = true;
            else foundAny = r;
            // Preceded by frame counter increment: inc dword ptr [reg+disp32] (FF 8x ?? ?? 00 00)
            if (i >= 6 && txt[i - 6] == 0xFF && (txt[i - 5] & 0xF8u) == 0x80u &&
                txt[i - 2] == 0x00 && txt[i - 1] == 0x00) {
                if (foundInc != 0 && foundInc != r) incAmbiguous = true;
                else foundInc = r;
            }
        }
    }
    if (!anyAmbiguous && foundAny != 0) return foundAny;
    if (!incAmbiguous && foundInc != 0) return foundInc;
    return 0;
}

uint32_t ResolveSetFpsFromLimitRva(const uint8_t* txt, size_t txtSz, uint32_t txtRva,
                                   uintptr_t baseAddr, bool is64, uint32_t fpsLimRva) {
    if (!txt || txtSz < 16 || !fpsLimRva) return 0;
    uint32_t found = 0;
    if (is64) {
        for (size_t i = 0; i + 7 <= txtSz; ++i) {
            if (txt[i] == 0x89 && txt[i + 1] == 0x0D && txt[i + 6] == 0xC3) {
                int32_t disp = 0;
                memcpy(&disp, txt + i + 2, 4);
                if (txtRva + static_cast<uint32_t>(i) + 6u + static_cast<uint32_t>(disp) == fpsLimRva) {
                    uint32_t r = txtRva + static_cast<uint32_t>(i);
                    if (found != 0 && found != r) return 0;
                    found = r;
                }
            }
        }
    } else {
        uint32_t targetVa = static_cast<uint32_t>(baseAddr) + fpsLimRva;
        static constexpr uint8_t kSetHead[7] = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xA3 };
        for (size_t i = 0; i + 13 <= txtSz; ++i) {
            if (memcmp(txt + i, kSetHead, sizeof(kSetHead)) == 0 &&
                txt[i + 11] == 0x5D && txt[i + 12] == 0xC3) {
                uint32_t va = 0;
                memcpy(&va, txt + i + 7, 4);
                if (va == targetVa) {
                    uint32_t r = txtRva + static_cast<uint32_t>(i);
                    if (found != 0 && found != r) return 0;
                    found = r;
                }
            }
        }
    }
    return found;
}

uint32_t FindRdataZeroFloatRva(const RdataSlice& rdata, uint32_t nearRva, bool is64, uint32_t instrNextRva) {
    if (rdata.rva == 0 || rdata.bytes.size() < 4) return 0;
    uint32_t bestRva = 0;
    uint64_t bestDist = UINT64_MAX;

    auto consider = [&](size_t off) {
        if (off + 4 > rdata.bytes.size()) return;
        if (rdata.bytes[off] == 0 && rdata.bytes[off + 1] == 0 &&
            rdata.bytes[off + 2] == 0 && rdata.bytes[off + 3] == 0) {
            uint32_t candRva = rdata.rva + static_cast<uint32_t>(off);
            if (is64) {
                int64_t disp = static_cast<int64_t>(candRva) - static_cast<int64_t>(instrNextRva);
                if (disp < INT32_MIN || disp > INT32_MAX) return;
            }
            uint64_t dist = (candRva >= nearRva) ? (candRva - nearRva) : (nearRva - candRva);
            if (dist < bestDist) {
                bestDist = dist;
                bestRva = candRva;
            }
        }
    };

    // Fast local window within 512 bytes around the original 0.1f slot first.
    if (nearRva >= rdata.rva && nearRva < rdata.rva + rdata.bytes.size()) {
        size_t center = static_cast<size_t>(nearRva - rdata.rva) & ~size_t(3);
        size_t lo = (center > 512) ? (center - 512) : 0;
        size_t hi = std::min(rdata.bytes.size(), center + 512);
        for (size_t off = lo; off + 4 <= hi; off += 4) {
            consider(off);
        }
        if (bestRva != 0) return bestRva;
    }

    for (size_t off = 0; off + 4 <= rdata.bytes.size(); off += 4) {
        consider(off);
    }
    return bestRva;
}

uint32_t ResolveX86SilAddEpilogue(const uint8_t* txt, size_t txtSz, uint32_t txtRva, uint32_t silAddDedupRva) {
    if (!txt || silAddDedupRva < txtRva) return 0;
    size_t baseOff = static_cast<size_t>(silAddDedupRva - txtRva);
    static constexpr uint8_t kEpilogue[9] = { 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00 };
    size_t scanStart = baseOff + 0x40;
    size_t scanEnd = std::min(txtSz, baseOff + 0x180);
    for (size_t i = scanStart; i + sizeof(kEpilogue) <= scanEnd; ++i) {
        if (memcmp(txt + i, kEpilogue, sizeof(kEpilogue)) == 0) {
            return txtRva + static_cast<uint32_t>(i);
        }
    }
    return 0;
}

uint32_t ResolveX86UpdSnap2(const uint8_t* txt, size_t txtSz, uint32_t txtRva, uint32_t updSnap1Rva) {
    if (!txt || updSnap1Rva < txtRva) return 0;
    size_t baseOff = static_cast<size_t>(updSnap1Rva - txtRva);
    size_t scanStart = baseOff + 8;
    size_t scanEnd = std::min(txtSz, baseOff + 64);
    for (size_t i = scanStart; i + 8 <= scanEnd; ++i) {
        if (txt[i] == 0xF3 && txt[i + 1] == 0x0F && txt[i + 2] == 0x10 && txt[i + 3] == 0x35) {
            return txtRva + static_cast<uint32_t>(i);
        }
    }
    return 0;
}

uint32_t ResolveX86PrecacheCamo2(const uint8_t* txt, size_t txtSz, uint32_t txtRva, uint32_t precacheCamo1Rva) {
    if (!txt || precacheCamo1Rva < txtRva) return 0;
    size_t baseOff = static_cast<size_t>(precacheCamo1Rva - txtRva);
    // Expect: [0..4] E8/90 RemoveCamo, then 53 56 E8 ?? ?? ?? ?? 56 (E8|90) RestoreCamo within +5..+24.
    if (baseOff + 24 > txtSz) return 0;
    for (size_t i = baseOff + 5; i + 13 <= baseOff + 24; ++i) {
        if (txt[i] == 0x53 && txt[i + 1] == 0x56 && txt[i + 2] == 0xE8 &&
            txt[i + 7] == 0x56 && (txt[i + 8] == 0xE8 || txt[i + 8] == 0x90)) {
            return txtRva + static_cast<uint32_t>(i + 8);
        }
    }
    return 0;
}

} // namespace cr1m
