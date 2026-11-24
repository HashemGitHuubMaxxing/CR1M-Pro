// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/aob.hpp"
#include "cr1m/win_runtime.hpp"
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace cr1m {

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
    for (size_t i = 0; i < pat.size(); ++i) {
        if (pat[i].b >= 0) { anchor = i; break; }
    }
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
    if (hits.size() == 1) return hits[0] + static_cast<uint32_t>(offset);
    return 0;
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

} // namespace cr1m
