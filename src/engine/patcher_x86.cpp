// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/patcher.hpp"
#include "cr1m/pacer.hpp"
#include "cr1m/vrr.hpp"
#include "cr1m/win_runtime.hpp"
#include <cstring>

namespace cr1m {

namespace {

bool ApplyPatchLogged(HANDLE hp, uintptr_t base, uint32_t rva, const void* d, size_t n,
                      PatchReport& rep, ModSessionState* sess) {
    if (rva && PatchVerified(hp, base, rva, d, n, sess)) {
        ++rep.okCount;
        return true;
    }
    ++rep.failCount;
    return false;
}

bool FixSnapAbsX86(HANDLE hp, uintptr_t base, uint32_t movssRva, const RdataSlice* rdata,
                   PatchReport& rep, ModSessionState* sess) {
    if (!movssRva) { ++rep.failCount; return false; }
    uint8_t insn[8]{};
    if (!ReadMem(hp, base + movssRva, insn, 8) ||
        insn[0] != 0xF3 || insn[1] != 0x0F || insn[2] != 0x10 || (insn[3] & 0xC7u) != 0x05u) {
        ++rep.failCount;
        return false;
    }
    uint32_t va = *reinterpret_cast<uint32_t*>(insn + 4);
    float cur = -1.0f, nxt = -1.0f;
    ReadMem(hp, static_cast<uintptr_t>(va), &cur, 4);
    ReadMem(hp, static_cast<uintptr_t>(va + 4), &nxt, 4);
    if (cur == 0.0f) { ++rep.okCount; return true; }
    if (cur == 0.1f && nxt == 0.0f) {
        uint32_t newVa = va + 4;
        return ApplyPatchLogged(hp, base, movssRva + 4, &newVa, 4, rep, sess);
    }
    if (cur == 0.1f && rdata != nullptr && va >= static_cast<uint32_t>(base)) {
        uint32_t nearRva = va - static_cast<uint32_t>(base);
        uint32_t zeroRva = FindRdataZeroFloatRva(*rdata, nearRva, false, movssRva + 8);
        if (zeroRva != 0) {
            uint32_t newVa = static_cast<uint32_t>(base) + zeroRva;
            return ApplyPatchLogged(hp, base, movssRva + 4, &newVa, 4, rep, sess);
        }
    }
    ++rep.failCount;
    return false;
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
                     const Kernel32Iat& iat, uint32_t targetFps, PatchReport& report,
                     const AuthProof& proof, ModSessionState* sess,
                     const RdataSlice* rdata, SigManifestProvider manifestProvider) {
    report = PatchReport{};
    if (!proof.isValid()) return false;
    const uint32_t caveMagic = proof.deriveCaveMagic();
    if (caveMagic == 0) return false;

    // 1. Tier 1 hardened primary AOBs + Tier 2 local structural fallbacks
    uint32_t rSwitchT = ScanAob(txt.data(), txt.size(), txtRva,
        "83 F8 01 75 ?? 8D 78 3B E9 ?? ?? 00 00 83 F8 02 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8", 18);

    uint32_t rLoopB = ScanAob(txt.data(), txt.size(), txtRva,
        "B8 E8 03 00 00 99 F7 ?? ?? 8B F0 B8 01 00 00 00 2B F1 83 FE 01 0F 4C F0 E8 ?? ?? ?? ?? 84 C0 74 ?? 56 FF|E8", 34);
    if (!rLoopB) {
        rLoopB = ResolveLoopBByIat(txt.data(), txt.size(), txtRva, base, false, iat.pSleepRva, hp, caveMagic);
    }

    uint32_t rGetFps = 0, rSetFps = 0;
    uint32_t rFpsPair = ScanAob(txt.data(), txt.size(), txtRva,
        "55 8B EC 8B 45 08 56 8B F1 89 06 C7 46 04 00 00 00 00 E8 ?? ?? ?? ?? FF 36 89 46 04 E8 ?? ?? ?? ?? 83 C4 04", 0);
    if (rFpsPair && (rFpsPair - txtRva) + 33 < txt.size()) {
        int32_t relG = *reinterpret_cast<const int32_t*>(&txt[(rFpsPair - txtRva) + 19]);
        int32_t relS = *reinterpret_cast<const int32_t*>(&txt[(rFpsPair - txtRva) + 29]);
        rGetFps = rFpsPair + 18 + 5 + static_cast<uint32_t>(relG);
        rSetFps = rFpsPair + 28 + 5 + static_cast<uint32_t>(relS);
    }
    if (!rGetFps && rLoopB) {
        rGetFps = ResolveGetFpsNearLoopB(txt.data(), txt.size(), txtRva, base, false, rLoopB);
    }

    auto extractFpsLimit = [&](uint32_t gRva, uint32_t sRva) -> uint32_t {
        uint8_t b[13]{};
        if (gRva && ReadMem(hp, base + gRva, b, 6) && b[0] == 0xA1) {
            uint32_t va = *reinterpret_cast<uint32_t*>(b + 1);
            if (va > static_cast<uint32_t>(base)) return va - static_cast<uint32_t>(base);
        }
        if (sRva && ReadMem(hp, base + sRva, b, 13) && b[0] == 0x55 && b[6] == 0xA3) {
            uint32_t va = *reinterpret_cast<uint32_t*>(b + 7);
            if (va > static_cast<uint32_t>(base)) return va - static_cast<uint32_t>(base);
        }
        return 0;
    };

    uint32_t fpsLimRva = extractFpsLimit(rGetFps, rSetFps);
    if (!rSetFps && fpsLimRva) {
        rSetFps = ResolveSetFpsFromLimitRva(txt.data(), txt.size(), txtRva, base, false, fpsLimRva);
    }

    uint32_t rWin10 = ScanAob(txt.data(), txt.size(), txtRva,
        "55|B0 8B|01 EC|C3 81 EC ?? ?? 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 FC 56 68 00 01 00 00 8D 85 ?? ?? FF FF C7 85 ?? ?? FF FF 1C 01 00 00", 0);

    uint32_t updRoundfLen = 48;
    uint32_t rUpdRoundf = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 10 45 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? F3 0F 10 2D ?? ?? ?? ?? 0F 57 ?? F3 0F 59", 5);
    if (!rUpdRoundf) {
        rUpdRoundf = ScanAob(txt.data(), txt.size(), txtRva,
            "F3 0F 10 45 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? F3 0F 10 2D ?? ?? ?? ?? 0F 57 ?? F3 0F 59", 5);
        if (rUpdRoundf) updRoundfLen = 54;
    }
    uint32_t rUpdSnap1 = ScanAob(txt.data(), txt.size(), txtRva,
        "0F 28 ?? 73 03 0F 57 ?? F3 0F 10 35 ?? ?? ?? ?? 0F 2F ?? 72 ?? 0F 28 C4 EB ?? F3 0F 59 CD F3 0F 58 C1 EB ?? F3 0F 10 35 ?? ?? ?? ?? F3 0F 10 0D", 8);
    uint32_t rUpdSnap2 = rUpdSnap1 ? ResolveX86UpdSnap2(txt.data(), txt.size(), txtRva, rUpdSnap1) : 0;
    uint32_t rUpdSnap3 = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 11 44 24 ?? EB 08 F3 0F 10 35 ?? ?? ?? ?? F3 0F 10 ?? 24 ?? F3 0F 10 64 24 ?? 0F 2E ??", 8);
    uint32_t rUpdRotSnap = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 10 1F F3 0F 10 2D ?? ?? ?? ?? F3 0F 10 35 ?? ?? ?? ?? 0F 2E CB 9F F6 C4 44 0F 8B", 12);
    uint32_t rUpdRotSnap2 = 0;
    if (!rUpdRotSnap) {
        auto rotHits = ScanAobAll(txt.data(), txt.size(), txtRva,
            "0F 28 C8 F3 0F 5C CB 0F 2F CA 0F 28 D1 73 07 0F 57 15 ?? ?? ?? ?? F3 0F 10 ?? ?? ?? ?? ?? 0F 2F ?? 73 0C 0F 28 C1 F3 0F 59 45 ?? F3 0F 58 C3");
        if (rotHits.size() == 2 && rotHits[1] > rotHits[0] && (rotHits[1] - rotHits[0]) < 0x300u) {
            rUpdRotSnap = rotHits[0] + 22u;
            rUpdRotSnap2 = rotHits[1] + 22u;
        } else if (rotHits.size() == 1) {
            rUpdRotSnap = rotHits[0] + 22u;
        }
    }
    uint32_t rRotBr = ScanAob(txt.data(), txt.size(), txtRva,
        "89 44 24 ?? 89 4C 24 ?? 75|74 ?? 80 BE ?? ?? 00 00 00 74 ?? F3 0F 10 5C 24 ?? F3 0F 10 54 24 ?? EB", 8);
    uint32_t rRotAcc = ScanAob(txt.data(), txt.size(), txtRva,
        "F3 0F 5E 8E ?? ?? 00 00 F3 0F 11 4C 24 ?? F3 0F 58|10 05 ?? ?? ?? ?? F3 0F 11 44 24 ?? 0F 28 E0", 14);

    uint32_t rSilVisDup = ScanAob(txt.data(), txt.size(), txtRva,
        "E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? EB 17|2D 8D 45 ?? C6 45 ?? 00", 32);
    uint32_t rSilAddDedup = ScanAob(txt.data(), txt.size(), txtRva,
        "56 53 E8 ?? ?? ?? ?? 8B 73 24 83 C4 08 8B 36 80 7E 0D 00 0F 85 ?? ?? ?? ?? 80 7D ?? 00 BB|0F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 8B 45 ?? 0F 57 C0 8B 7E 10", 25);
    uint32_t rSilAddTail = ScanAob(txt.data(), txt.size(), txtRva,
        "80 7E 0D 00 0F 84 ?? ?? ?? ?? 8B 5D ?? 80 7D ?? 00 75|EB 0B 6A 00 53 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 8B E5 5D C2 04 00", 17);
    uint32_t rSilKeepCacheHeal = ScanAob(txt.data(), txt.size(), txtRva,
        "3B 73 3C 74 03 89 73 3C 80 7B 34 00 75|EB 0C 8D 45 08 50 8D 4B 44 E8 ?? ?? ?? ?? 8B 4D ??", 12);
    uint32_t rPrecacheCamo1 = ScanAob(txt.data(), txt.size(), txtRva,
        "8B CE 6A 01 E8 ?? ?? ?? ?? 56 E8|90 ?? ?? ?? ?? 53 56 E8 ?? ?? ?? ?? 56 E8|90 ?? ?? ?? ?? 8B 8D ?? ?? FF FF 83 C4 10", 10);
    uint32_t rPrecacheCamo2 = rPrecacheCamo1 ? ResolveX86PrecacheCamo2(txt.data(), txt.size(), txtRva, rPrecacheCamo1) : 0;

    // 2. Tier 3 RSA 2048 signed remote hotfix manifest (ONLY invoked when 1+ required slot missed locally)
    auto hasAnyMissing = [&]() -> bool {
        return !rSwitchT || !rLoopB || !rGetFps || !rSetFps || !rWin10 ||
               !rUpdRoundf || !rUpdSnap1 || !rUpdSnap2 || !rUpdSnap3 || !rUpdRotSnap ||
               !rRotBr || !rRotAcc || !rSilVisDup || !rSilAddDedup || !rSilAddTail ||
               !rPrecacheCamo1 || !rPrecacheCamo2;
    };

    if (manifestProvider && hasAnyMissing()) {
        for (int pass = 0; pass < 2 && hasAnyMissing(); ++pass) {
            SignedSigManifest mf{};
            if (!manifestProvider(false, pass == 1, mf)) continue;
            if (CompareSemver(mf.latestModVersion, kModVersion) > 0) {
                report.newerVersionAvailable = mf.latestModVersion;
            }
            auto trySlot = [&](uint32_t& dst, const char* slotName) {
                if (dst) return;
                uint32_t cand = EvaluateManifestRulesForSlot(txt.data(), txt.size(), txtRva, mf, slotName);
                if (cand) {
                    dst = cand;
                    report.usedRemoteHotfix = true;
                }
            };
            trySlot(rSwitchT, "SwitchT");
            trySlot(rLoopB, "LoopB");
            trySlot(rGetFps, "GetFps");
            trySlot(rSetFps, "SetFps");
            trySlot(rWin10, "Win10");
            trySlot(rUpdRoundf, "UpdRoundf");
            trySlot(rUpdSnap1, "UpdSnap1");
            if (!rUpdSnap2 && rUpdSnap1) {
                rUpdSnap2 = ResolveX86UpdSnap2(txt.data(), txt.size(), txtRva, rUpdSnap1);
            }
            trySlot(rUpdSnap2, "UpdSnap2");
            trySlot(rUpdSnap3, "UpdSnap3");
            trySlot(rUpdRotSnap, "UpdRotSnap");
            trySlot(rRotBr, "RotBr");
            trySlot(rRotAcc, "RotAcc");
            trySlot(rSilVisDup, "SilVisDup");
            trySlot(rSilAddDedup, "SilAddDedup");
            trySlot(rSilAddTail, "SilAddTail");
            trySlot(rPrecacheCamo1, "PrecacheCamo1");
            if (!rPrecacheCamo2 && rPrecacheCamo1) {
                rPrecacheCamo2 = ResolveX86PrecacheCamo2(txt.data(), txt.size(), txtRva, rPrecacheCamo1);
            }
            trySlot(rPrecacheCamo2, "PrecacheCamo2");

            if (!rGetFps && rLoopB) {
                rGetFps = ResolveGetFpsNearLoopB(txt.data(), txt.size(), txtRva, base, false, rLoopB);
            }
            if (!fpsLimRva) fpsLimRva = extractFpsLimit(rGetFps, rSetFps);
            if (!rSetFps && fpsLimRva) {
                rSetFps = ResolveSetFpsFromLimitRva(txt.data(), txt.size(), txtRva, base, false, fpsLimRva);
            }
        }
    }

    if (!fpsLimRva) fpsLimRva = extractFpsLimit(rGetFps, rSetFps);

    // 3. Apply Core FPS Unlock & Win10 patches atomically
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
        ApplyPatchLogged(hp, base, fpsLimRva, fpsB, 4, report, sess);
    }

    bool gfOk = false, sfOk = false, w10Ok = false;
    if (rGetFps) {
        uint8_t gf[6] = { 0xB8, fpsB[0], fpsB[1], fpsB[2], fpsB[3], 0xC3 };
        gfOk = ApplyPatchLogged(hp, base, rGetFps, gf, 6, report, sess);
    } else {
        ++report.failCount;
    }

    if (rSetFps) {
        static constexpr uint8_t sf[13] = { 0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
        sfOk = ApplyPatchLogged(hp, base, rSetFps, sf, sizeof(sf), report, sess);
    } else {
        ++report.failCount;
    }

    if (rWin10) {
        static constexpr uint8_t w10[3] = { 0xB0, 0x01, 0xC3 };
        if (sess) {
            uint8_t curW10[3]{};
            if (ReadMem(hp, base + rWin10, curW10, 3) && memcmp(curW10, w10, 3) != 0) {
                sess->win10WasUnpatched = true;
            }
        }
        w10Ok = ApplyPatchLogged(hp, base, rWin10, w10, sizeof(w10), report, sess);
    } else {
        ++report.failCount;
    }

    // 4. Precision 1:1 Aim fixes
    bool rbOk = false, raOk = false, rfOk = false;
    if (rRotBr) {
        uint8_t curBr[2]{};
        if (ReadMem(hp, base + rRotBr, curBr, 2) && (curBr[0] == 0x74 || curBr[0] == 0x75)) {
            uint8_t rb[2] = { 0x75, curBr[1] };
            rbOk = ApplyPatchLogged(hp, base, rRotBr, rb, sizeof(rb), report, sess);
        } else {
            ++report.failCount;
        }
    } else {
        ++report.failCount;
    }

    if (rRotAcc) {
        uint8_t insn[8]{};
        if (ReadMem(hp, base + rRotAcc, insn, 8) &&
            insn[0] == 0xF3 && insn[1] == 0x0F && (insn[2] == 0x58 || insn[2] == 0x10) && insn[3] == 0x05) {
            uint32_t absVa = *reinterpret_cast<uint32_t*>(insn + 4);
            float fval = 0.0f;
            ReadMem(hp, static_cast<uintptr_t>(absVa), &fval, 4);
            if (fval == 1.0f) {
                const uint8_t op = 0x10;
                raOk = ApplyPatchLogged(hp, base, rRotAcc + 2, &op, 1, report, sess);
            } else {
                ++report.failCount;
            }
        } else {
            ++report.failCount;
        }
    } else {
        ++report.failCount;
    }

    if (rUpdRoundf) {
        if (updRoundfLen == 54) {
            uint8_t cur[15]{};
            if (ReadMem(hp, base + rUpdRoundf, cur, sizeof(cur))) {
                if (cur[0] == 0xF3 && cur[1] == 0x0F && cur[2] == 0x11 && cur[3] == 0x4C && cur[4] == 0x24 &&
                    cur[6] == 0xEB && cur[7] == 0x2E) {
                    ++report.okCount;
                    rfOk = true;
                } else if (cur[8] == 0x51 && cur[9] == 0xF3 && cur[10] == 0x0F && cur[11] == 0x11 &&
                           cur[12] == 0x4C && cur[13] == 0x24 && cur[14] >= 4u) {
                    uint8_t r54[54];
                    memset(r54, 0x90, sizeof(r54));
                    r54[0] = 0xF3; r54[1] = 0x0F; r54[2] = 0x11; r54[3] = 0x4C; r54[4] = 0x24;
                    r54[5] = static_cast<uint8_t>(cur[14] - 4u);
                    r54[6] = 0xEB; r54[7] = 0x2E;
                    rfOk = ApplyPatchLogged(hp, base, rUpdRoundf, r54, sizeof(r54), report, sess);
                } else {
                    ++report.failCount;
                }
            } else {
                ++report.failCount;
            }
        } else {
            uint8_t r48[48];
            memset(r48, 0x90, sizeof(r48));
            r48[0] = 0xEB; r48[1] = 0x2E;
            rfOk = ApplyPatchLogged(hp, base, rUpdRoundf, r48, sizeof(r48), report, sess);
        }
    } else {
        ++report.failCount;
    }

    bool sn1Ok = FixSnapAbsX86(hp, base, rUpdSnap1, rdata, report, sess);
    bool sn2Ok = FixSnapAbsX86(hp, base, rUpdSnap2, rdata, report, sess);
    bool sn3Ok = FixSnapAbsX86(hp, base, rUpdSnap3, rdata, report, sess);
    bool sn4Ok = FixSnapAbsX86(hp, base, rUpdRotSnap, rdata, report, sess);
    if (rUpdRotSnap2) {
        sn4Ok = sn4Ok && FixSnapAbsX86(hp, base, rUpdRotSnap2, rdata, report, sess);
    }
    report.aimOk = rbOk && raOk && rfOk && sn1Ok && sn2Ok && sn3Ok && sn4Ok;

    // 5. Silhouette Spotting Hitch & Precache Camouflage Fixes
    bool svOk = false, saOk = false, stOk = false, c1Ok = false, c2Ok = false;
    if (rSilVisDup) {
        uint8_t curJmp = 0;
        if (ReadMem(hp, base + rSilVisDup, &curJmp, 1) && (curJmp == 0x17 || curJmp == 0x2D)) {
            const uint8_t jmpSkip = 0x2D;
            svOk = ApplyPatchLogged(hp, base, rSilVisDup, &jmpSkip, 1, report, sess);
        } else {
            ++report.failCount;
        }
    } else {
        ++report.failCount;
    }

    if (rSilAddDedup) {
        uint32_t epilogueRva = ResolveX86SilAddEpilogue(txt.data(), txt.size(), txtRva, rSilAddDedup);
        uint8_t hdr[4]{};
        if (epilogueRva > rSilAddDedup + 10u && ReadMem(hp, base + rSilAddDedup, hdr, 4) &&
            hdr[0] == 0x80 && hdr[1] == 0x7D && hdr[3] == 0x00) {
            uint32_t jeRel = epilogueRva - (rSilAddDedup + 10u);
            uint8_t dedup[17] = {
                0x80, 0x7D, hdr[2], 0x00,                 // cmp byte ptr [ebp+disp8], 0
                0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,       // je epilogueRva
                0xBB, 0xE0, 0x00, 0x00, 0x00,             // mov ebx, 224 (0xE0)
                0x66, 0x90                                // nop
            };
            memcpy(dedup + 6, &jeRel, 4);
            saOk = ApplyPatchLogged(hp, base, rSilAddDedup, dedup, sizeof(dedup), report, sess);
        } else {
            ++report.failCount;
        }
    } else {
        ++report.failCount;
    }

    if (rSilAddTail) {
        uint8_t curTail = 0;
        if (ReadMem(hp, base + rSilAddTail, &curTail, 1) && (curTail == 0x75 || curTail == 0xEB)) {
            const uint8_t jmpTail = 0xEB;
            stOk = ApplyPatchLogged(hp, base, rSilAddTail, &jmpTail, 1, report, sess);
        } else {
            ++report.failCount;
        }
    } else {
        ++report.failCount;
    }

    if (rSilKeepCacheHeal) {
        uint8_t curByte = 0;
        if (ReadMem(hp, base + rSilKeepCacheHeal, &curByte, 1) && curByte == 0xEB) {
            const uint8_t origJne = 0x75;
            PatchVerified(hp, base, rSilKeepCacheHeal, &origJne, 1, nullptr);
        }
    }

    if (rPrecacheCamo1 && rPrecacheCamo2) {
        static constexpr uint8_t nops5[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
        c1Ok = ApplyPatchLogged(hp, base, rPrecacheCamo1, nops5, sizeof(nops5), report, sess);
        c2Ok = ApplyPatchLogged(hp, base, rPrecacheCamo2, nops5, sizeof(nops5), report, sess);
    } else {
        report.failCount += 2;
    }
    report.spottingOk = svOk && saOk && stOk && c1Ok && c2Ok;

    // 6. Deploy 32 bit Pacer + SwitchT Trampoline
    bool swOk = false;
    if (rLoopB && iat.pQpcRva && iat.pSleepRva) {
        LARGE_INTEGER qf{};
        QueryPerformanceFrequency(&qf);
        uint64_t ticks = static_cast<uint64_t>(qf.QuadPart) / targetFps;

        uint32_t switchJoinVa = 0;
        if (rSwitchT) {
            uint8_t curSw[8]{};
            ReadMem(hp, base + rSwitchT, curSw, 8);
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
        }

        uint8_t curLb[6]{};
        ReadMem(hp, base + rLoopB, curLb, 6);
        uintptr_t existingCave = 0;
        if (curLb[0] == 0xE8) {
            int32_t rel = *reinterpret_cast<int32_t*>(curLb + 1);
            uintptr_t cand = base + rLoopB + 5 + rel;
            uint32_t mag = 0;
            if (cand >= 0x60 && ReadMem(hp, cand - 0x60, &mag, 4) && mag == caveMagic) {
                existingCave = cand - 0x60;
            }
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
            if (switchJoinVa) {
                runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(existingCave + 0x281), &targetFps, 4, &bw);
                swOk = true;
            }
            FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(existingCave), 0x300);
            if (sess) sess->caveBase = existingCave;
            ++report.okCount;
            report.pacerOk = true;
            if (!swOk) ++report.failCount;
        } else if (curLb[0] == 0xFF && curLb[1] == 0x15) {
            uintptr_t caveBase = reinterpret_cast<uintptr_t>(
                runtime::DynVirtualAllocEx(hp, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!caveBase || caveBase > 0xFFFF0000ULL) {
                ++report.failCount;
            } else {
                auto cave = BuildX86Cave(static_cast<uint32_t>(caveBase), targetFps, ticks,
                                         static_cast<uint32_t>(base + iat.pQpcRva),
                                         static_cast<uint32_t>(base + iat.pSleepRva),
                                         switchJoinVa ? switchJoinVa : static_cast<uint32_t>(caveBase + 0x280),
                                         proof);
                if (cave.size() < 0x28A) {
                    ++report.failCount;
                } else {
                    memcpy(cave.data() + 0x50, &initLeaseQpc, 8);
                    SIZE_T bw = 0;
                    if (!runtime::DynWriteProcessMemory(hp, reinterpret_cast<LPVOID>(caveBase), cave.data(), cave.size(), &bw) ||
                        bw != cave.size()) {
                        ++report.failCount;
                    } else {
                        FlushInstructionCache(hp, reinterpret_cast<LPCVOID>(caveBase), cave.size());
                        if (sess) sess->caveBase = caveBase;

                        int32_t relLb = static_cast<int32_t>(static_cast<uint32_t>(caveBase + 0x60) -
                                                             (static_cast<uint32_t>(base) + rLoopB + 5));
                        uint8_t lbHook[6] = { 0xE8, 0, 0, 0, 0, 0x90 };
                        memcpy(lbHook + 1, &relLb, 4);
                        report.pacerOk = ApplyPatchLogged(hp, base, rLoopB, lbHook, 6, report, sess);

                        if (rSwitchT && switchJoinVa) {
                            int32_t relSw = static_cast<int32_t>(static_cast<uint32_t>(caveBase + 0x280) -
                                                                 (static_cast<uint32_t>(base) + rSwitchT + 5));
                            uint8_t swHook[8] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90 };
                            memcpy(swHook + 1, &relSw, 4);
                            swOk = ApplyPatchLogged(hp, base, rSwitchT, swHook, 8, report, sess);
                        } else {
                            ++report.failCount;
                        }
                    }
                }
            }
        } else {
            ++report.failCount;
        }
    } else {
        ++report.failCount;
        if (!rSwitchT) ++report.failCount;
    }

    report.fpsCoreOk = swOk && gfOk && sfOk && w10Ok;
    return report.okCount > 0 && report.failCount == 0;
}

} // namespace cr1m
