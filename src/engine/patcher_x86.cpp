// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/patcher.hpp"
#include "cr1m/pacer.hpp"
#include "cr1m/vrr.hpp"
#include "cr1m/win_runtime.hpp"
#include <cstring>

namespace cr1m {

namespace {

void ApplyPatchLogged(HANDLE hp, uintptr_t base, uint32_t rva, const void* d, size_t n,
                      int& okCount, int& failCount, ModSessionState* sess) {
    if (rva && PatchVerified(hp, base, rva, d, n, sess)) ++okCount;
    else ++failCount;
}

void FixSnapAbsX86(HANDLE hp, uintptr_t base, uint32_t movssRva,
                   int& okCount, int& failCount, ModSessionState* sess) {
    if (!movssRva) { ++failCount; return; }
    uint8_t insn[8]{};
    if (!ReadMem(hp, base + movssRva, insn, 8) ||
        insn[0] != 0xF3 || insn[1] != 0x0F || insn[2] != 0x10 || insn[3] != 0x35) {
        ++failCount;
        return;
    }
    uint32_t va = *reinterpret_cast<uint32_t*>(insn + 4);
    float cur = -1.0f, nxt = -1.0f;
    ReadMem(hp, static_cast<uintptr_t>(va), &cur, 4);
    ReadMem(hp, static_cast<uintptr_t>(va + 4), &nxt, 4);
    if (cur == 0.0f) { ++okCount; return; }
    if (cur == 0.1f && nxt == 0.0f) {
        uint32_t newVa = va + 4;
        ApplyPatchLogged(hp, base, movssRva + 4, &newVa, 4, okCount, failCount, sess);
    } else {
        ++failCount;
    }
}

} // namespace

void ApplySystemPerformanceOptimizations(HANDLE hProc, DWORD pid, ModSessionState* sess) {
    if (sess) {
        sess->origPriority = GetPriorityClass(hProc);
        if (!sess->origPriority) sess->origPriority = NORMAL_PRIORITY_CLASS;
    }
    SetPriorityClass(hProc, HIGH_PRIORITY_CLASS);

    auto pSetProcessInfo = runtime::Api().pSetProcInfo;
    if (pSetProcessInfo) {
        PROCESS_POWER_THROTTLING_STATE pt{};
        pt.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
        pt.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
        pt.StateMask = 0;
        if (!pSetProcessInfo(hProc, ProcessPowerThrottling, &pt, sizeof(pt))) {
            pt.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
            pSetProcessInfo(hProc, ProcessPowerThrottling, &pt, sizeof(pt));
        }
    }
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);

    wchar_t exePath[MAX_PATH * 2]{};
    DWORD exeLen = static_cast<DWORD>(sizeof(exePath) / sizeof(exePath[0]));
    if (runtime::DynQueryFullProcessImageNameW(hProc, 0, exePath, &exeLen) && exeLen > 0) {
        EnsureExeGpuPreferences(exePath);
    }

    HKEY hkDvr = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"System\\GameConfigStore", 0, NULL, 0, KEY_SET_VALUE, NULL, &hkDvr, NULL) == ERROR_SUCCESS) {
        DWORD dvr = 0, fse = 2;
        RegSetValueExW(hkDvr, L"GameDVR_Enabled", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dvr), 4);
        RegSetValueExW(hkDvr, L"GameDVR_FSEBehaviorMode", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&fse), 4);
        RegCloseKey(hkDvr);
    }

    HANDLE hSnap = runtime::DynCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        DWORD mainTid = 0;
        uint64_t earliestCreate = UINT64_MAX;
        if (runtime::DynThread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    if (mainTid == 0) mainTid = te.th32ThreadID;
                    HANDLE ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                    if (ht) {
                        FILETIME ftC{}, ftE{}, ftK{}, ftU{};
                        if (GetThreadTimes(ht, &ftC, &ftE, &ftK, &ftU)) {
                            uint64_t ct = (static_cast<uint64_t>(ftC.dwHighDateTime) << 32) | ftC.dwLowDateTime;
                            if (ct < earliestCreate) { earliestCreate = ct; mainTid = te.th32ThreadID; }
                        }
                        CloseHandle(ht);
                    }
                }
            } while (runtime::DynThread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
        if (mainTid != 0) {
            HANDLE ht = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, mainTid);
            if (ht) {
                if (sess) {
                    sess->mainTid = mainTid;
                    int tp = GetThreadPriority(ht);
                    sess->origThreadPrio = (tp != THREAD_PRIORITY_ERROR_RETURN) ? tp : THREAD_PRIORITY_NORMAL;
                }
                SetThreadPriority(ht, THREAD_PRIORITY_HIGHEST);
                CloseHandle(ht);
            }
        }
    }
}

void RevertModEffects(ModSessionState& sess) {
    if (!sess.hProc || sess.backups.empty()) return;
    if (WaitForSingleObject(sess.hProc, 0) != WAIT_TIMEOUT) {
        sess.backups.clear();
        return;
    }

    {
        ScopedProcessFreeze freeze(sess.hProc);
        if (sess.caveBase) {
            uint32_t fps60 = 60;
            uint64_t zeroTicks = 0;
            uint64_t expiredLease = 1ULL;
            SIZE_T bw = 0;
            runtime::DynWriteProcessMemory(sess.hProc, reinterpret_cast<LPVOID>(sess.caveBase + 0x04), &fps60, 4, &bw);
            runtime::DynWriteProcessMemory(sess.hProc, reinterpret_cast<LPVOID>(sess.caveBase + 0x08), &zeroTicks, 8, &bw);
            runtime::DynWriteProcessMemory(sess.hProc, reinterpret_cast<LPVOID>(sess.caveBase + 0x50), &expiredLease, 8, &bw);
            FlushInstructionCache(sess.hProc, reinterpret_cast<LPCVOID>(sess.caveBase), 0x300);
        }

        for (auto it = sess.backups.rbegin(); it != sess.backups.rend(); ++it) {
            DWORD oldProt = 0;
            LPVOID addr = reinterpret_cast<LPVOID>(sess.baseAddr + it->rva);
            if (runtime::DynVirtualProtectEx(sess.hProc, addr, it->orig.size(), PAGE_EXECUTE_READWRITE, &oldProt)) {
                SIZE_T bw = 0;
                runtime::DynWriteProcessMemory(sess.hProc, addr, it->orig.data(), it->orig.size(), &bw);
                FlushInstructionCache(sess.hProc, addr, it->orig.size());
                DWORD dummy = 0;
                runtime::DynVirtualProtectEx(sess.hProc, addr, it->orig.size(), oldProt, &dummy);
            }
        }

        if (sess.fpsLimRva) {
            DWORD oldProt = 0;
            LPVOID addr = reinterpret_cast<LPVOID>(sess.baseAddr + sess.fpsLimRva);
            if (runtime::DynVirtualProtectEx(sess.hProc, addr, 4, PAGE_READWRITE, &oldProt)) {
                SIZE_T bw = 0;
                runtime::DynWriteProcessMemory(sess.hProc, addr, &sess.origFpsLimit, 4, &bw);
                DWORD dummy = 0;
                runtime::DynVirtualProtectEx(sess.hProc, addr, 4, oldProt, &dummy);
            }
        }
    }

    Sleep(30);
    if (sess.origPriority) SetPriorityClass(sess.hProc, sess.origPriority);
    if (sess.mainTid) {
        HANDLE ht = OpenThread(THREAD_SET_INFORMATION, FALSE, sess.mainTid);
        if (ht) {
            SetThreadPriority(ht, sess.origThreadPrio);
            CloseHandle(ht);
        }
    }
    sess.backups.clear();
}

bool ApplyPatchesX86(HANDLE hp, uintptr_t base, const std::vector<uint8_t>& txt, uint32_t txtRva,
                     const Kernel32Iat& iat, uint32_t targetFps, int& okCount, int& failCount,
                     const AuthProof& proof, ModSessionState* sess) {
    if (!proof.isValid()) return false;
    const uint32_t caveMagic = proof.deriveCaveMagic();
    if (caveMagic == 0) return false;

    uint32_t rSwitchT = ScanAob(txt.data(), txt.size(), txtRva,
        "83 F8 01 75 08 8D 78 3B E9 ?? ?? 00 00 83 F8 02 75 08 ?? ?? ?? ?? ?? ?? ?? ?? E8", 18);

    uint32_t rGetFps = 0, rSetFps = 0;
    uint32_t rFpsPair = ScanAob(txt.data(), txt.size(), txtRva,
        "55 8B EC 8B 45 08 56 8B F1 89 06 C7 46 04 00 00 00 00 E8 ?? ?? ?? ?? FF 36 89 46 04 E8 ?? ?? ?? ?? 83 C4 04", 0);
    if (rFpsPair && (rFpsPair - txtRva) + 33 < txt.size()) {
        int32_t relG = *reinterpret_cast<const int32_t*>(&txt[(rFpsPair - txtRva) + 19]);
        int32_t relS = *reinterpret_cast<const int32_t*>(&txt[(rFpsPair - txtRva) + 29]);
        rGetFps = rFpsPair + 18 + 5 + static_cast<uint32_t>(relG);
        rSetFps = rFpsPair + 28 + 5 + static_cast<uint32_t>(relS);
    }

    uint32_t rWin10 = ScanAob(txt.data(), txt.size(), txtRva,
        "55|B0 8B|01 EC|C3 81 EC 20 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 FC 56 68 00 01 00 00 8D 85 F4 FE FF FF C7 85 E0 FE FF FF 1C 01 00 00", 0);
    uint32_t rLoopB = ScanAob(txt.data(), txt.size(), txtRva,
        "B8 E8 03 00 00 99 F7 7D ?? 8B F0 B8 01 00 00 00 2B F1 83 FE 01 0F 4C F0 E8 ?? ?? ?? ?? 84 C0 74 07 56 FF|E8 ?? ?? ?? ?? ?? 80 7D", 34);

    uint32_t rUpdRoundf = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 10 45 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? F3 0F 10 2D ?? ?? ?? ?? 0F 57 DB F3 0F 59", 5);
    uint32_t rUpdSnap1 = ScanAob(txt.data(), txt.size(), txtRva,
        "0F 28 D1 73 03 0F 57 D7 F3 0F 10 35 ?? ?? ?? ?? 0F 2F F2 72 05 0F 28 C4 EB 12 F3 0F 59 CD F3 0F 58 C1 EB 08 F3 0F 10 35 ?? ?? ?? ?? F3 0F 10 0D", 8);
    uint32_t rUpdSnap3 = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 11 44 24 10 EB 08 F3 0F 10 35 ?? ?? ?? ?? F3 0F 10 54 24 0C F3 0F 10 64 24 18 0F 2E D4", 8);
    uint32_t rUpdRotSnap = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 10 1F F3 0F 10 2D ?? ?? ?? ?? F3 0F 10 35 ?? ?? ?? ?? 0F 2E CB 9F F6 C4 44 0F 8B", 12);
    uint32_t rRotBr = ScanAob(txt.data(), txt.size(), txtRva,
        "89 44 24 20 89 4C 24 24 75|74 17 80 BE ?? ?? 00 00 00 74 0E F3 0F 10 5C 24 24 F3 0F 10 54 24 20 EB 2C", 8);
    uint32_t rRotAcc = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 5E 8E ?? ?? 00 00 F3 0F 11 4C 24 14 F3 0F 58|10 05 ?? ?? ?? ?? F3 0F 11 44 24 10 0F 28 E0", 14);

    // Silhouette hitch & stall elimination AOBs
    uint32_t rSilVisDup = ScanAob(txt.data(), txt.size(), txtRva,
        "E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? EB 17|2D 8D 45 B8 C6 45 CC 00", 32);
    uint32_t rSilAddDedup = ScanAob(txt.data(), txt.size(), txtRva,
        "56 53 E8 ?? ?? ?? ?? 8B 73 24 83 C4 08 8B 36 80 7E 0D 00 0F 85 ?? ?? ?? ?? 80 7D FC 00 BB|0F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 8B 45 DD 0F 57 C0 8B 7E 10", 25);
    uint32_t rSilAddTail = ScanAob(txt.data(), txt.size(), txtRva,
        "80 7E 0D 00 0F 84 ?? ?? ?? ?? 8B 5D F8 80 7D FC 00 75|EB 0B 6A 00 53 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 8B E5 5D C2 04 00", 17);
    uint32_t rSilKeepCacheHeal = ScanAob(txt.data(), txt.size(), txtRva,
        "3B 73 3C 74 03 89 73 3C 80 7B 34 00 75|EB 0C 8D 45 08 50 8D 4B 44 E8 ?? ?? ?? ?? 8B 4D F4", 12);
    uint32_t rPrecacheCamo = ScanAob(txt.data(), txt.size(), txtRva,
        "8B CE 6A 01 E8 ?? ?? ?? ?? 56 E8|90 ?? ?? ?? ?? 53 56 E8 ?? ?? ?? ?? 56 E8|90 ?? ?? ?? ?? 8B 8D A8 FB FF FF 83 C4 10", 10);

    if (!rSwitchT || !rLoopB || !rGetFps || !rSetFps || !rWin10) {
        return false;
    }

    // Extract fpsLimit VA (ASLR-safe) before patching GetFps / SetFps
    uint32_t fpsLimRva = 0;
    {
        uint8_t b[13]{};
        if (ReadMem(hp, base + rGetFps, b, 6) && b[0] == 0xA1) {
            uint32_t va = *reinterpret_cast<uint32_t*>(b + 1);
            if (va > static_cast<uint32_t>(base)) fpsLimRva = va - static_cast<uint32_t>(base);
        } else if (ReadMem(hp, base + rSetFps, b, 13) && b[0] == 0x55 && b[6] == 0xA3) {
            uint32_t va = *reinterpret_cast<uint32_t*>(b + 7);
            if (va > static_cast<uint32_t>(base)) fpsLimRva = va - static_cast<uint32_t>(base);
        }
    }

    ScopedProcessFreeze freeze(hp);
    uint8_t fpsB[4];
    memcpy(fpsB, &targetFps, 4);
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

    uint8_t gf[6] = { 0xB8, fpsB[0], fpsB[1], fpsB[2], fpsB[3], 0xC3 };
    ApplyPatchLogged(hp, base, rGetFps, gf, 6, okCount, failCount, sess);
    static constexpr uint8_t sf[13] = { 0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
    ApplyPatchLogged(hp, base, rSetFps, sf, sizeof(sf), okCount, failCount, sess);
    static constexpr uint8_t w10[3] = { 0xB0, 0x01, 0xC3 };
    if (sess) {
        uint8_t curW10[3]{};
        if (ReadMem(hp, base + rWin10, curW10, 3) && memcmp(curW10, w10, 3) != 0) {
            sess->win10WasUnpatched = true;
        }
    }
    ApplyPatchLogged(hp, base, rWin10, w10, sizeof(w10), okCount, failCount, sess);

    // Precision 1:1 Aim fixes
    if (rRotBr) {
        static constexpr uint8_t rb[2] = { 0x75, 0x17 };
        ApplyPatchLogged(hp, base, rRotBr, rb, sizeof(rb), okCount, failCount, sess);
    } else ++failCount;

    if (rRotAcc) {
        uint8_t insn[8]{};
        if (ReadMem(hp, base + rRotAcc, insn, 8) && insn[0] == 0xF3 && insn[1] == 0x0F && insn[3] == 0x05) {
            uint32_t absVa = *reinterpret_cast<uint32_t*>(insn + 4);
            float fval = 0.0f;
            ReadMem(hp, static_cast<uintptr_t>(absVa), &fval, 4);
            if (fval == 1.0f) {
                const uint8_t op = 0x10;
                ApplyPatchLogged(hp, base, rRotAcc + 2, &op, 1, okCount, failCount, sess);
            } else ++failCount;
        } else ++failCount;
    } else ++failCount;

    if (rUpdRoundf) {
        uint8_t r48[48];
        memset(r48, 0x90, sizeof(r48));
        r48[0] = 0xEB; r48[1] = 0x2E;
        ApplyPatchLogged(hp, base, rUpdRoundf, r48, sizeof(r48), okCount, failCount, sess);
    } else ++failCount;

    FixSnapAbsX86(hp, base, rUpdSnap1, okCount, failCount, sess);
    FixSnapAbsX86(hp, base, rUpdSnap1 ? rUpdSnap1 + 28 : 0, okCount, failCount, sess);
    FixSnapAbsX86(hp, base, rUpdSnap3, okCount, failCount, sess);
    FixSnapAbsX86(hp, base, rUpdRotSnap, okCount, failCount, sess);

    // Silhouette Spotting Hitch & Precache Camouflage Fixes
    if (rSilVisDup) {
        const uint8_t jmpSkip = 0x2D;
        ApplyPatchLogged(hp, base, rSilVisDup, &jmpSkip, 1, okCount, failCount, sess);
    } else ++failCount;

    if (rSilAddDedup) {
        static constexpr uint8_t dedup[17] = {
            0x80, 0x7D, 0xFC, 0x00,                   // cmp byte ptr [ebp-4], 0
            0x0F, 0x84, 0xEF, 0x00, 0x00, 0x00,       // je +0xEF
            0xBB, 0xE0, 0x00, 0x00, 0x00,             // mov ebx, 224 (0xE0)
            0x66, 0x90                                // nop
        };
        ApplyPatchLogged(hp, base, rSilAddDedup, dedup, sizeof(dedup), okCount, failCount, sess);
    } else ++failCount;

    if (rSilAddTail) {
        const uint8_t jmpTail = 0xEB;
        ApplyPatchLogged(hp, base, rSilAddTail, &jmpTail, 1, okCount, failCount, sess);
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
        ApplyPatchLogged(hp, base, rPrecacheCamo + 13, nops5, sizeof(nops5), okCount, failCount, sess);
    } else {
        failCount += 2;
    }

    // Deploy 32-bit Pacer + SwitchT Trampoline
    if (iat.pQpcRva && iat.pSleepRva) {
        LARGE_INTEGER qf{};
        QueryPerformanceFrequency(&qf);
        uint64_t ticks = static_cast<uint64_t>(qf.QuadPart) / targetFps;

        uint8_t curSw[8]{};
        ReadMem(hp, base + rSwitchT, curSw, 8);
        uint32_t switchJoinVa = 0;
        if (curSw[0] == 0x8D && curSw[3] == 0xE9) {
            int32_t jRel = *reinterpret_cast<int32_t*>(curSw + 4);
            switchJoinVa = static_cast<uint32_t>(base) + rSwitchT + 8 + static_cast<uint32_t>(jRel);
        } else if (curSw[0] == 0xE9) {
            int32_t tRel = *reinterpret_cast<int32_t*>(curSw + 1);
            uint32_t tramp = static_cast<uint32_t>(base) + rSwitchT + 5 + static_cast<uint32_t>(tRel);
            uint8_t tr[10]{};
            if (ReadMem(hp, tramp, tr, 10) && tr[0] == 0xBF && tr[5] == 0xE9) {
                switchJoinVa = tramp + 10 + *reinterpret_cast<uint32_t*>(tr + 6);
            }
        }

        uint8_t curLb[6]{};
        ReadMem(hp, base + rLoopB, curLb, 6);
        uintptr_t existingCave = 0;
        if (curLb[0] == 0xE8) {
            int32_t rel = *reinterpret_cast<int32_t*>(curLb + 1);
            uintptr_t cand = base + rLoopB + 5 + rel;
            uint32_t mag = 0;
            if (ReadMem(hp, cand - 0x60, &mag, 4) && mag == caveMagic) existingCave = cand - 0x60;
        }

        LARGE_INTEGER qn{};
        QueryPerformanceCounter(&qn);
        uint64_t initLeaseQpc = proof.computeInitialLeaseQpc(static_cast<uint64_t>(qn.QuadPart),
                                                             static_cast<uint64_t>(qf.QuadPart));

        if (existingCave) {
            SIZE_T bw = 0;
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x04), &targetFps, 4, &bw);
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x08), &ticks, 8, &bw);
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x50), &initLeaseQpc, 8, &bw);
            runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x281), &targetFps, 4, &bw);
            FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(existingCave), 0x300);
            if (sess) sess->caveBase = existingCave;
            ++okCount;
        } else if (switchJoinVa) {
            uintptr_t caveBase = reinterpret_cast<uintptr_t>(
                runtime::DynVirtualAllocEx(hp, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!caveBase || caveBase > 0xFFFF0000ULL) { ++failCount; return false; }
            auto cave = BuildX86Cave(static_cast<uint32_t>(caveBase), targetFps, ticks,
                                     static_cast<uint32_t>(base + iat.pQpcRva),
                                     static_cast<uint32_t>(base + iat.pSleepRva),
                                     switchJoinVa, proof);
            if (cave.size() < 0x28A) { ++failCount; return false; }
            memcpy(cave.data() + 0x50, &initLeaseQpc, 8);
            SIZE_T bw = 0;
            if (!runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(caveBase), cave.data(), cave.size(), &bw) ||
                bw != cave.size()) {
                ++failCount;
                return false;
            }
            FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(caveBase), cave.size());
            if (sess) sess->caveBase = caveBase;

            int32_t relLb = static_cast<int32_t>(static_cast<uint32_t>(caveBase + 0x60) -
                                                 (static_cast<uint32_t>(base) + rLoopB + 5));
            uint8_t lbHook[6] = { 0xE8, 0, 0, 0, 0, 0x90 };
            memcpy(lbHook + 1, &relLb, 4);
            ApplyPatchLogged(hp, base, rLoopB, lbHook, 6, okCount, failCount, sess);

            int32_t relSw = static_cast<int32_t>(static_cast<uint32_t>(caveBase + 0x280) -
                                                 (static_cast<uint32_t>(base) + rSwitchT + 5));
            uint8_t swHook[8] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90 };
            memcpy(swHook + 1, &relSw, 4);
            ApplyPatchLogged(hp, base, rSwitchT, swHook, 8, okCount, failCount, sess);
        } else ++failCount;
    } else ++failCount;

    return failCount == 0;
}

} // namespace cr1m
