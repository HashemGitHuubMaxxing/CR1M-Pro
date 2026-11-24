// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/patcher.hpp"
#include "cr1m/pacer.hpp"
#include "cr1m/win_runtime.hpp"
#include <climits>
#include <cstring>

namespace cr1m {

namespace {

void ApplyPatchLogged(HANDLE hp, uintptr_t base, uint32_t rva, const void* d, size_t n,
                      int& okCount, int& failCount, ModSessionState* sess) {
    if (rva && PatchVerified(hp, base, rva, d, n, sess)) ++okCount;
    else ++failCount;
}

void FixSnapDispX64(HANDLE hp, uintptr_t base, uint32_t dispRva,
                    int& okCount, int& failCount, ModSessionState* sess) {
    if (!dispRva) { ++failCount; return; }
    int32_t disp = 0;
    if (!ReadMem(hp, base + dispRva, &disp, 4)) { ++failCount; return; }
    uintptr_t target = base + dispRva + 4 + static_cast<int64_t>(disp);
    float cur = -1.0f, nxt = -1.0f;
    ReadMem(hp, target, &cur, 4);
    ReadMem(hp, target + 4, &nxt, 4);
    if (cur == 0.0f) { ++okCount; return; }
    if (cur == 0.1f && nxt == 0.0f) {
        int32_t newDisp = disp + 4;
        ApplyPatchLogged(hp, base, dispRva, &newDisp, 4, okCount, failCount, sess);
    } else {
        ++failCount;
    }
}

} // namespace

bool ApplyPatchesX64(HANDLE hp, uintptr_t base, const std::vector<uint8_t>& txt, uint32_t txtRva,
                     const Kernel32Iat& iat, uint32_t targetFps, int& okCount, int& failCount,
                     const AuthProof& proof, ModSessionState* sess) {
    if (!proof.isValid()) return false;
    const uint32_t caveMagic = proof.deriveCaveMagic();
    if (caveMagic == 0) return false;

    // 1. Locate key targets with primary AOB + resilient caller fallbacks
    uint32_t rSwitchT = ScanAob(txt.data(), txt.size(), txtRva,
        "8B 7C 24 40 83 F8 01 75 0A BF 3C 00 00 00 E9 ?? ?? 00 00 83 F8 02 75 0A BF ?? ?? ?? ?? E9 ?? ?? 00 00 E8", 24);
    uint32_t rLoopB = ScanAob(txt.data(), txt.size(), txtRva,
        "B8 E8 03 00 00 99 F7 FE 8B D8 2B D9 83 FB 01 41 0F 4C DC E8 ?? ?? ?? ?? 84 C0 74 08 8B CB FF|E8 ?? ?? ?? ?? ?? 40 84 FF 0F 84", 30);

    uint32_t rGetFps = ScanAob(txt.data(), txt.size(), txtRva,
        "24 50 48 83 C4 20 41 5F 41 5E 5F C3 8B C6 EB E3 8B 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC 8B|B8 ?? ?? ?? ?? ?? C3|90 CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 8B 0D", 32);
    if (!rGetFps) {
        uint32_t callSite = ScanAob(txt.data(), txt.size(), txtRva,
            "FF 83 48 01 00 00 E8 ?? ?? ?? ?? 8B F0 48 8D 4D E0", 6);
        if (callSite) {
            int32_t rel = *reinterpret_cast<const int32_t*>(&txt[(callSite - txtRva) + 1]);
            rGetFps = callSite + 5 + static_cast<uint32_t>(rel);
        }
    }

    uint32_t fpsLimRva = 0;
    if (rGetFps) {
        uint8_t b[7]{};
        if (ReadMem(hp, base + rGetFps, b, 7) && b[0] == 0x8B && b[1] == 0x05) {
            int32_t disp = *reinterpret_cast<int32_t*>(b + 2);
            fpsLimRva = rGetFps + 6 + static_cast<uint32_t>(disp);
        }
    }

    uint32_t rSetFps = ScanAob(txt.data(), txt.size(), txtRva,
        "49 8B 73 28 49 8B E3 41 5E 5F 5D C3 CC CC CC 89|C3 ?? ?? ?? ?? ?? C3|90 CC CC CC CC CC CC CC CC CC 48 89 5C 24 18 48 89 74 24 20 88 54 24 10 57 48", 15);
    if (rSetFps && !fpsLimRva) {
        uint8_t b[7]{};
        if (ReadMem(hp, base + rSetFps, b, 7) && b[0] == 0x89 && b[1] == 0x0D) {
            int32_t disp = *reinterpret_cast<int32_t*>(b + 2);
            fpsLimRva = rSetFps + 6 + static_cast<uint32_t>(disp);
        }
    } else if (!rSetFps && fpsLimRva) {
        for (size_t i = 0; i + 7 <= txt.size(); ++i) {
            if (txt[i] == 0x89 && txt[i + 1] == 0x0D && txt[i + 6] == 0xC3) {
                int32_t disp = *reinterpret_cast<const int32_t*>(&txt[i + 2]);
                if (txtRva + static_cast<uint32_t>(i) + 6 + static_cast<uint32_t>(disp) == fpsLimRva) {
                    rSetFps = txtRva + static_cast<uint32_t>(i);
                    break;
                }
            }
        }
    }

    uint32_t rWin10 = ScanAob(txt.data(), txt.size(), txtRva,
        "83 3C 90 01 0F 94 C3 80 7C 24 38 00 74 0A 48 8B 4C 24 30 E8 ?? ?? ?? ?? 0F B6 C3 48 83 C4 40 5B C3 CC CC CC CC CC CC CC CC CC CC CC CC CC CC", 47);
    if (!rWin10) {
        uint32_t dxCall = ScanAob(txt.data(), txt.size(), txtRva,
            "48 8D 94 24 C0 00 00 00 FF 50 18 90 E8 ?? ?? ?? ?? 48 8D 94 24 C0 00 00 00", 12);
        if (dxCall) {
            int32_t rel = *reinterpret_cast<const int32_t*>(&txt[(dxCall - txtRva) + 1]);
            rWin10 = dxCall + 5 + static_cast<uint32_t>(rel);
        }
    }

    uint32_t rUpdSnap = ScanAob(txt.data(), txt.size(), txtRva,
        "0F 10 25 ?? ?? ?? ?? F3 0F 10 1D ?? ?? ?? ?? F3 0F 5F 05 ?? ?? ?? ?? F3 0F 5D D0 7A 02 74 ?? 83 BF", 11);
    uint32_t rUpdRotSnap = ScanAob(txt.data(), txt.size(), txtRva,
        "8B BC 24 ?? 00 00 00 48 8B 9C 24 ?? 00 00 00 F3 0F 10 25 ?? ?? ?? ?? F3 0F 10 2D ?? ?? ?? ?? 7A 06 0F 84 ?? ?? 00 00 83 BE", 27);
    uint32_t rUpdRoundf = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 44 0F 10 54 24 30 41 0F 28 C4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 0F 2E FA ?? ?? ?? ?? ?? ?? ?? ?? F3 0F 10 15 ?? ?? ?? ?? F3 0F 59 87", 11);
    uint32_t rRotBr = ScanAob(txt.data(), txt.size(), txtRva,
        "48 89 84 24 A0 00 00 00 75|74 1D 80 BB ?? ?? 00 00 00 74 14 F3 0F 10 B4 24 A4 00 00 00", 8);
    uint32_t rRotAcc = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 44 0F 5E 8B ?? ?? 00 00 F3 44 0F 58|10 05 ?? ?? ?? ?? 45 0F 28 D0", 9);

    // Silhouette hitch & stall elimination AOBs
    uint32_t rSilVisDup = ScanAob(txt.data(), txt.size(), txtRva,
        "48 8B 4B 20 48 83 79 58 00 74 48 80 3E 00 74 0B 40 0F B6 D5 E8 ?? ?? ?? ?? EB 1D|38 C6 44 24 44 00 C6 44 24 4C 00 48 8D 54 24 30 E8", 26);
    uint32_t rSilAddDedup = ScanAob(txt.data(), txt.size(), txtRva,
        "48 8B 30 48 83 C6 18 4C 8B C6 E8 ?? ?? ?? ?? 40 0F B6 D7 48 8B CE E8 ?? ?? ?? ?? 48|40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75|5E 6E|38 ?? ?? ?? ?? ?? ?? ?? 00|75 00|74 48 8B 4B 20 40 0F B6 D7 E8 ?? ?? ?? ?? 48 8B 4B 10 80 79 19 00", 27);
    uint32_t rSilKeepCacheHeal = ScanAob(txt.data(), txt.size(), txtRva,
        "48 3B 5E 50 74 04 48 89 5E 50 80 7E 40 00 75|EB 11 48 8D 4E 60 48 8D 94 24 F8 01 00 00 E8 ?? ?? ?? ?? 48 8B 9C 24 00 02 00 00", 14);
    uint32_t rPrecacheCamo = ScanAob(txt.data(), txt.size(), txtRva,
        "B2 01 49 8B CD E8 ?? ?? ?? ?? 49 8B CD E8|90 ?? ?? ?? ?? 49 8B D7 49 8B CD E8 ?? ?? ?? ?? 49 8B CD E8|90", 13);

    if (!rSwitchT || !rLoopB || !rGetFps || !rSetFps || !rWin10) {
        return false;
    }

    // 2. Apply Core FPS Unlock & Win10 patches atomically
    ScopedProcessFreeze freeze(hp);
    uint8_t fpsB[4];
    memcpy(fpsB, &targetFps, 4);
    uint8_t sw[5] = { 0xBF, fpsB[0], fpsB[1], fpsB[2], fpsB[3] };
    ApplyPatchLogged(hp, base, rSwitchT, sw, 5, okCount, failCount, sess);
    if (fpsLimRva) {
        if (sess) {
            sess->fpsLimRva = fpsLimRva;
            uint32_t curLim = 60;
            if (ReadMem(hp, base + fpsLimRva, &curLim, 4) && curLim >= 30 && curLim <= 120) {
                sess->origFpsLimit = curLim;
            }
        }
        ApplyPatchLogged(hp, base, fpsLimRva, fpsB, 4, okCount, failCount, sess);
    }

    uint8_t gf[7] = { 0xB8, fpsB[0], fpsB[1], fpsB[2], fpsB[3], 0xC3, 0x90 };
    ApplyPatchLogged(hp, base, rGetFps, gf, 7, okCount, failCount, sess);
    static constexpr uint8_t sf[7]  = { 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    ApplyPatchLogged(hp, base, rSetFps, sf, sizeof(sf), okCount, failCount, sess);
    static constexpr uint8_t w10[3] = { 0xB0, 0x01, 0xC3 };
    ApplyPatchLogged(hp, base, rWin10, w10, sizeof(w10), okCount, failCount, sess);

    // 3. Apply Verified Precision 1:1 Aim Fixes
    if (rRotBr) {
        static constexpr uint8_t rb[2] = { 0x75, 0x1D };
        ApplyPatchLogged(hp, base, rRotBr, rb, sizeof(rb), okCount, failCount, sess);
    } else ++failCount;

    if (rRotAcc) {
        uint8_t insn[9]{};
        if (ReadMem(hp, base + rRotAcc, insn, 9) &&
            insn[0] == 0xF3 && insn[1] == 0x44 && insn[2] == 0x0F && insn[4] == 0x05) {
            int32_t disp = *reinterpret_cast<int32_t*>(insn + 5);
            float fval = 0.0f;
            ReadMem(hp, base + rRotAcc + 9 + disp, &fval, 4);
            if (fval == 1.0f) {
                const uint8_t op = 0x10;
                ApplyPatchLogged(hp, base, rRotAcc + 3, &op, 1, okCount, failCount, sess);
            } else ++failCount;
        } else ++failCount;
    } else ++failCount;

    if (rUpdRoundf) {
        uint8_t cmp[4]{};
        if (ReadMem(hp, base + rUpdRoundf + 13, cmp, 4) &&
            cmp[0] == 0x41 && cmp[1] == 0x0F && cmp[2] == 0x2E && cmp[3] == 0xFA) {
            static constexpr uint8_t n13[13] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
            static constexpr uint8_t n8[8]   = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
            ApplyPatchLogged(hp, base, rUpdRoundf, n13, sizeof(n13), okCount, failCount, sess);
            ApplyPatchLogged(hp, base, rUpdRoundf + 17, n8, sizeof(n8), okCount, failCount, sess);
        } else ++failCount;
    } else ++failCount;

    FixSnapDispX64(hp, base, rUpdSnap, okCount, failCount, sess);
    FixSnapDispX64(hp, base, rUpdRotSnap, okCount, failCount, sess);

    // 3b. Silhouette Spotting Hitch & Precache Camouflage Fixes
    if (rSilVisDup) {
        const uint8_t jmpSkip = 0x38;
        ApplyPatchLogged(hp, base, rSilVisDup, &jmpSkip, 1, okCount, failCount, sess);
    } else ++failCount;

    if (rSilAddDedup) {
        static constexpr uint8_t dedup[22] = {
            0x40, 0x84, 0xFF,                         // test dil, dil
            0x0F, 0x84, 0x81, 0x00, 0x00, 0x00,       // je +0x81 (epilogue)
            0x48, 0x8B, 0x5E, 0x38,                   // mov rbx, [rsi+56]
            0x48, 0x8B, 0x1B,                         // mov rbx, [rbx]
            0x80, 0x7B, 0x19, 0x00,                   // cmp byte ptr [rbx+25], 0
            0x75, 0x74                                // jne +0x74 (epilogue)
        };
        ApplyPatchLogged(hp, base, rSilAddDedup, dedup, sizeof(dedup), okCount, failCount, sess);
    } else ++failCount;

    if (rSilKeepCacheHeal) {
        uint8_t curByte = 0;
        if (ReadMem(hp, base + rSilKeepCacheHeal, &curByte, 1) && curByte == 0xEB) {
            const uint8_t origJne = 0x75;
            PatchVerified(hp, base, rSilKeepCacheHeal, &origJne, 1, nullptr);
        }
    }

    if (rPrecacheCamo) {
        static constexpr uint8_t nops5[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
        ApplyPatchLogged(hp, base, rPrecacheCamo, nops5, sizeof(nops5), okCount, failCount, sess);
        ApplyPatchLogged(hp, base, rPrecacheCamo + 19, nops5, sizeof(nops5), okCount, failCount, sess);
    } else {
        failCount += 2;
    }

    // 4. Deploy Dynamic Pacer Cave
    if (iat.pQpcRva && iat.pSleepRva) {
        LARGE_INTEGER qf{}, qn{};
        QueryPerformanceFrequency(&qf);
        QueryPerformanceCounter(&qn);
        uint64_t ticks = static_cast<uint64_t>(qf.QuadPart) / targetFps;
        uint64_t initLeaseQpc = proof.computeInitialLeaseQpc(static_cast<uint64_t>(qn.QuadPart),
                                                             static_cast<uint64_t>(qf.QuadPart));

        uint8_t curCall[6]{};
        ReadMem(hp, base + rLoopB, curCall, 6);
        uintptr_t existingCave = 0;
        if (curCall[0] == 0xE8) {
            int32_t rel = *reinterpret_cast<int32_t*>(curCall + 1);
            uintptr_t cand = base + rLoopB + 5 + static_cast<int64_t>(rel);
            uint32_t mag = 0;
            if (ReadMem(hp, cand - 0x60, &mag, 4) && mag == caveMagic) {
                existingCave = cand - 0x60;
            }
        }

        if (existingCave) {
            uint32_t newFps = targetFps;
            SIZE_T bw = 0;
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x04), &newFps, 4, &bw);
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x08), &ticks, 8, &bw);
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x50), &initLeaseQpc, 8, &bw);
            FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(existingCave), 0x60);
            if (sess) sess->caveBase = existingCave;
            ++okCount;
        } else {
            uintptr_t caveBase = AllocNearModule(hp, base + rLoopB, 4096);
            if (!caveBase) { ++failCount; return false; }
            auto cave = BuildX64Cave(targetFps, ticks, base + iat.pQpcRva, base + iat.pSleepRva, proof);
            if (cave.size() < 0x60) { ++failCount; return false; }
            memcpy(cave.data() + 0x50, &initLeaseQpc, 8);
            SIZE_T bw = 0;
            if (!runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(caveBase), cave.data(), cave.size(), &bw) ||
                bw != cave.size()) {
                ++failCount;
                return false;
            }
            FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(caveBase), cave.size());
            if (sess) sess->caveBase = caveBase;
            int64_t rel64 = static_cast<int64_t>(caveBase + 0x60) - static_cast<int64_t>(base + rLoopB + 5);
            if (rel64 < INT32_MIN || rel64 > INT32_MAX) { ++failCount; return false; }
            int32_t rel32 = static_cast<int32_t>(rel64);
            uint8_t hook[6] = { 0xE8, 0, 0, 0, 0, 0x90 };
            memcpy(hook + 1, &rel32, 4);
            ApplyPatchLogged(hp, base, rLoopB, hook, 6, okCount, failCount, sess);
        }
    } else ++failCount;

    return failCount == 0;
}

} // namespace cr1m
