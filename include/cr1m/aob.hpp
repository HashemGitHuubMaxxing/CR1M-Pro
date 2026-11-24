// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace cr1m {

struct PatElem {
    int16_t b;
    uint8_t a1;
    uint8_t a2;
};

struct PatchBackup {
    uint32_t rva = 0;
    std::vector<uint8_t> orig;
};

struct ModSessionState {
    HANDLE hProc = NULL;
    DWORD pid = 0;
    uintptr_t baseAddr = 0;
    bool is64 = true;
    uintptr_t caveBase = 0;
    uint32_t fpsLimRva = 0;
    uint32_t origFpsLimit = 60;
    DWORD origPriority = NORMAL_PRIORITY_CLASS;
    DWORD mainTid = 0;
    int origThreadPrio = THREAD_PRIORITY_NORMAL;
    bool win10WasUnpatched = false;
    std::vector<PatchBackup> backups;

    void recordOriginal(uint32_t rva, const std::vector<uint8_t>& curBytes);
};

struct Kernel32Iat {
    uint32_t pQpcRva = 0;
    uint32_t pSleepRva = 0;
};

class ScopedProcessFreeze final {
public:
    explicit ScopedProcessFreeze(HANDLE hp);
    ~ScopedProcessFreeze();
    ScopedProcessFreeze(const ScopedProcessFreeze&) = delete;
    ScopedProcessFreeze& operator=(const ScopedProcessFreeze&) = delete;

private:
    HANDLE hProc_ = NULL;
    bool frozen_ = false;
};

uintptr_t            GetWotbModuleBase(DWORD pid);
std::vector<PatElem> ParseAobPattern(const char* s);
std::vector<uint32_t> ScanAobAll(const uint8_t* buf, size_t sz, uint32_t baseRva, const char* patStr);
uint32_t             ScanAob(const uint8_t* buf, size_t sz, uint32_t baseRva, const std::string& patStr, int offset);
bool                 ReadMem(HANDLE hp, uintptr_t addr, void* out, size_t len);
bool                 PatchVerified(HANDLE hp, uintptr_t base, uint32_t rva, const void* data, size_t len,
                                   ModSessionState* sess = nullptr);
Kernel32Iat          ResolveKernel32Iat(HANDLE hp, uintptr_t base, bool is64, uint32_t impRva, uint32_t impSz);

} // namespace cr1m
