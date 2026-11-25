// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/aob.hpp"
#include "cr1m/auth.hpp"
#include "cr1m/auth_proof.hpp"
#include "cr1m/build_config.hpp"
#include "cr1m/clients.hpp"
#include "cr1m/config.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/patcher.hpp"
#include "cr1m/trial.hpp"
#include "cr1m/util.hpp"
#include "cr1m/vrr.hpp"
#include "cr1m/win_runtime.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {
    using namespace cr1m;

    if (!runtime::InitWinApis()) {
        return 1;
    }

    PurgeLegacyDebugLogs();
    CleanupPreviousOtaBackup();
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    if constexpr (kBuildChannelId == 1u) {
        SetConsoleTitleA("CR1M Pro Mod");
    } else {
        std::string title = std::string("CR1M Pro Mod [") + kBuildChannelLabel + "]";
        SetConsoleTitleA(title.c_str());
    }
    InitWatchdogCtrlLock();
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    timeBeginPeriod(1);

    bool nonInteractive = false;
    bool noOta = false;
    bool resetLang = false;
    std::string cliLang;
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "--noprompt") == 0 || _stricmp(argv[i], "--no-prompt") == 0) {
            nonInteractive = true;
        } else if (_stricmp(argv[i], "--no-ota") == 0) {
            noOta = true;
        } else if (_stricmp(argv[i], "--reset-lang") == 0) {
            resetLang = true;
        } else if (_stricmp(argv[i], "--lang=ru") == 0) {
            cliLang = "RU";
        } else if (_stricmp(argv[i], "--lang=en") == 0) {
            cliLang = "EN";
        }
    }

    if (!noOta) {
        StartAsyncOtaUpdateCheck();
    }

    ModConfig cfg = LoadConfig();
    ResolveUiLanguage(cfg.language, cliLang, resetLang, nonInteractive);

    SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    ConPrint("============================================================================\n");
    ConPrint("                                CR1M Pro Mod\n");
    ConPrint(TR(" This modification is delivered by CR1M, and I hope you enjoy your experience.\n",
                "   \xD0\x9C\xD0\xBE\xD0\xB4\xD0\xB8\xD1\x84\xD0\xB8\xD0\xBA\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F \xD0\xBF\xD1\x80\xD0\xB5\xD0\xB4\xD0\xBE\xD1\x81\xD1\x82\xD0\xB0\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB0 CR1M \xE2\x80\x94 \xD0\xBF\xD1\x80\xD0\xB8\xD1\x8F\xD1\x82\xD0\xBD\xD0\xBE\xD0\xB9 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B \xD0\xB8 \xD0\xBF\xD0\xBB\xD0\xB0\xD0\xB2\xD0\xBD\xD0\xBE\xD0\xB3\xD0\xBE \xD0\xBE\xD1\x82\xD0\xBA\xD0\xBB\xD0\xB8\xD0\xBA\xD0\xB0.\n"));
    ConPrint("============================================================================\n\n");
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // [1/5] License / Free Test Drive & AuthProof capability minting
    AuthSession auth;
    std::optional<AuthProof> proof = EnsureAuthOrTrial(nonInteractive, auth);
    if (!proof || !proof->isValid()) {
        timeEndPeriod(1);
        return 1;
    }
    if (auth.licensed) {
        ConPrint(TR("  [1/5] License Verified      : Active (",
                    "  [1/5] \xD0\x9F\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD0\xBA\xD0\xB0 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8     : \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xBD\xD0\xB0 (") +
                 MaskLicenseKeyForDisplay(auth.licenseKey) + ")\n");
    } else {
        std::ostringstream os;
        os << TR("  [1/5] Test Drive Mode       : Active (",
                 "  [1/5] \xD0\xA0\xD0\xB5\xD0\xB6\xD0\xB8\xD0\xBC \xD1\x82\xD0\xB5\xD1\x81\xD1\x82-\xD0\xB4\xD1\x80\xD0\xB0\xD0\xB9\xD0\xB2\xD0\xB0     : \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB5\xD0\xBD (")
           << std::setw(2) << std::setfill('0') << (auth.trialRemainingSec / 60) << ":"
           << std::setw(2) << std::setfill('0') << (auth.trialRemainingSec % 60)
           << TR(" remaining)\n", " \xD0\xBE\xD1\x81\xD1\x82\xD0\xB0\xD0\xBB\xD0\xBE\xD1\x81\xD1\x8C)\n");
        ConPrint(os.str());
    }

    // [2/5] Preflight Hardware Topology, Monitor Hz & VRR Audit
    int monitorHz = DetectMaxMonitorHz();
    int targetFps = ComputeSafeTargetFps(cfg, monitorHz);
    RunVrrPreflight(cfg, nonInteractive, *proof);
    {
        std::ostringstream os;
        os << TR("        -> Display Refresh    : ",
                 "        -> \xD0\xA7\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD1\x82\xD0\xB0 \xD1\x8D\xD0\xBA\xD1\x80\xD0\xB0\xD0\xBD\xD0\xB0     : ")
           << monitorHz << TR(" Hz -> Target ", " \xD0\x93\xD1\x86 -> \xD0\xA6\xD0\xB5\xD0\xBB\xD1\x8C ")
           << targetFps << TR(" FPS (Safe Ceiling <=154)\n",
                              " FPS (\xD0\xB1\xD0\xB5\xD0\xB7\xD0\xBE\xD0\xBF\xD0\xB0\xD1\x81\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xBB\xD0\xB8\xD0\xBC\xD0\xB8\xD1\x82 <=154)\n");
        ConPrint(os.str());
    }

    if (!noOta && !nonInteractive) {
        SignedReleaseManifest startupOta{};
        if (TryConsumeVerifiedOtaUpdate(startupOta, 0)) {
            SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            ConPrint(TR("\n  [!] Update Available        : CR1M Pro Mod v",
                        "\n  [!] \xD0\x94\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xBD\xD0\xBE \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 : CR1M Pro Mod v") +
                     startupOta.version + TR(" (verified RSA 2048 signed release)\n",
                                             " (\xD0\xBF\xD0\xBE\xD0\xB4\xD0\xBF\xD0\xB8\xD1\x81\xD0\xB0\xD0\xBD\xD0\xBD\xD1\x8B\xD0\xB9 \xD1\x80\xD0\xB5\xD0\xBB\xD0\xB8\xD0\xB7 RSA 2048)\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            ConPrint(TR("      Press U + ENTER to install cleanly now, or press ENTER to skip and launch: ",
                        "      \xD0\x9D\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 U + ENTER \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBA\xD0\xB8 \xD0\xB8\xD0\xBB\xD0\xB8 ENTER \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xBF\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA\xD0\xB0: "));
            std::string ans;
            if (std::getline(std::cin, ans)) {
                std::string t = Trim(ans);
                std::string u = ToUpperAscii(t);
                if (!u.empty() && (u[0] == 'U' || t.find("\xD0\x93") == 0 || t.find("\xD0\xB3") == 0)) {
                    if (PerformVerifiedOtaUpdate(startupOta)) {
                        proof->revoke();
                        timeEndPeriod(1);
                        return 0;
                    }
                }
            }
            ConPrint("\n");
        }
    }

    // [3/5]..[5/5] Multi store client launch, patching, and interactive client switcher loop
    std::string nextSelectedStore;
    int lastExitCode = 0;
    while (true) {
        ConPrint(TR("  [3/5] Client Selection      : Scanning installed World of Tanks Blitz editions...\n",
                    "  [3/5] \xD0\x92\xD1\x8B\xD0\xB1\xD0\xBE\xD1\x80 \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82\xD0\xB0         : \xD0\x9F\xD0\xBE\xD0\xB8\xD1\x81\xD0\xBA \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xBD\xD1\x8B\xD1\x85 \xD0\xB2\xD0\xB5\xD1\x80\xD1\x81\xD0\xB8\xD0\xB9 World of Tanks Blitz...\n"));
        ClientInventory inv = DiscoverClients();
        std::string selectedStore = nextSelectedStore.empty()
            ? SelectTargetClient(cfg, inv, nonInteractive)
            : nextSelectedStore;
        nextSelectedStore.clear();
        std::string launchedStore = "ATTACHED";
        DWORD pid = 0;

        if (selectedStore.empty()) {
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            ConPrint(TR("  [!] No supported World of Tanks Blitz client detected. Start the game manually and retry.\n",
                        "  [!] \xD0\x9F\xD0\xBE\xD0\xB4\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB6\xD0\xB8\xD0\xB2\xD0\xB0\xD0\xB5\xD0\xBC\xD1\x8B\xD0\xB9 \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82 World of Tanks Blitz \xD0\xBD\xD0\xB5 \xD0\xBD\xD0\xB0\xD0\xB9\xD0\xB4\xD0\xB5\xD0\xBD. \xD0\x97\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x83 \xD0\xB2\xD1\x80\xD1\x83\xD1\x87\xD0\xBD\xD1\x83\xD1\x8E.\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        } else {
            pid = FindWotbPid(selectedStore);
            if (pid != 0) {
                launchedStore = selectedStore + "_ATTACHED";
                if (selectedStore == "STEAM" && !inv.steamExe.empty()) {
                    EnsureExeGpuPreferences(inv.steamExe);
                }
                ConPrint(TR("        -> Selected Client    : ",
                            "        -> \xD0\x92\xD1\x8B\xD0\xB1\xD1\x80\xD0\xB0\xD0\xBD\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82   : ") +
                         selectedStore +
                         TR(" (Attached to PID ", " (\xD0\x9F\xD0\xBE\xD0\xB4\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB5\xD0\xBD\xD0\xBE \xD0\xBA PID ") +
                         std::to_string(pid) + ")\n");
            } else if (LaunchSpecificStore(selectedStore, inv)) {
                launchedStore = selectedStore;
                ConPrint(TR("        -> Launching Client   : ",
                            "        -> \xD0\x97\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82\xD0\xB0     : ") +
                         selectedStore + "...\n");
            } else {
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                ConPrint(TR("  [!] Could not launch ", "  [!] \xD0\x9D\xD0\xB5 \xD1\x83\xD0\xB4\xD0\xB0\xD0\xBB\xD0\xBE\xD1\x81\xD1\x8C \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD1\x8C ") +
                         selectedStore +
                         TR(". Please start it manually.\n",
                            ". \xD0\x9F\xD0\xBE\xD0\xB6\xD0\xB0\xD0\xBB\xD1\x83\xD0\xB9\xD1\x81\xD1\x82\xD0\xB0, \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xB5\xD0\xB3\xD0\xBE \xD0\xB2\xD1\x80\xD1\x83\xD1\x87\xD0\xBD\xD1\x83\xD1\x8E.\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
        }

        HANDLE hProc = NULL;
        uintptr_t baseAddr = 0;
        bool is64 = true;
        uint32_t textRva = 0, textSz = 0, rdataRva = 0, rdataSz = 0, impRva = 0, impSz = 0;
        ModSessionState sess{};
        std::vector<uint8_t> txtBuf;
        RdataSlice rdata{};
        Kernel32Iat iat{};
        PatchReport report{};
        bool allOk = false;
        bool trialGuardAborted = false;
        DWORD ignorePid = 0;
        std::string pidStoreFilter = selectedStore.empty() ? std::string("AUTO") : selectedStore;

        for (int syncPass = 0; syncPass < 2; ++syncPass) {
            // [4/5] Synchronize with initialized engine & detect architecture
            ConPrint(TR("  [4/5] Engine Synchronization: Waiting for game code initialization...\n",
                        "  [4/5] \xD0\xA1\xD0\xB8\xD0\xBD\xD1\x85\xD1\x80\xD0\xBE\xD0\xBD\xD0\xB8\xD0\xB7\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F \xD0\xB4\xD0\xB2\xD0\xB8\xD0\xB6\xD0\xBA\xD0\xB0  : \xD0\x9E\xD0\xB6\xD0\xB8\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 \xD0\xB8\xD0\xBD\xD0\xB8\xD1\x86\xD0\xB8\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xB7\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8 \xD0\xB8\xD0\xB3\xD1\x80\xD0\xBE\xD0\xB2\xD0\xBE\xD0\xB3\xD0\xBE \xD0\xBA\xD0\xBE\xD0\xB4\xD0\xB0...\n"));
            hProc = NULL;
            baseAddr = 0;
            is64 = true;
            textRva = 0;
            textSz = 0;
            rdataRva = 0;
            rdataSz = 0;
            impRva = 0;
            impSz = 0;
            rdata = RdataSlice{};
            report = PatchReport{};
            allOk = false;
            trialGuardAborted = false;
            DWORD lastOpenErr = 0;
            int accessDeniedStreak = 0;

            for (int i = 0; i < 600; ++i) {
                bool foundReady = false;
                bool aborted = false;

                if (pid == 0) pid = FindWotbPid(pidStoreFilter, ignorePid);
                if (pid != 0) {
                    baseAddr = GetWotbModuleBase(pid);
                    if (baseAddr != 0) {
                        hProc = runtime::DynOpenProcess(
                            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                            PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_DUP_HANDLE |
                            PROCESS_SUSPEND_RESUME | SYNCHRONIZE,
                            FALSE, pid);
                        if (!hProc) {
                            hProc = runtime::DynOpenProcess(
                                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_DUP_HANDLE |
                                SYNCHRONIZE,
                                FALSE, pid);
                        }
                        if (!hProc) {
                            lastOpenErr = GetLastError();
                            if (lastOpenErr == ERROR_ACCESS_DENIED && ++accessDeniedStreak >= 5) {
                                aborted = true;
                            }
                        } else {
                            accessDeniedStreak = 0;
                            PROCESS_MEMORY_COUNTERS pmc{};
                            if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)) && pmc.WorkingSetSize > 50 * 1024 * 1024) {
                                IMAGE_DOS_HEADER dos{};
                                if (ReadMem(hProc, baseAddr, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
                                    IMAGE_FILE_HEADER fh{};
                                    uint32_t sig = 0;
                                    ReadMem(hProc, baseAddr + static_cast<uintptr_t>(dos.e_lfanew), &sig, 4);
                                    ReadMem(hProc, baseAddr + static_cast<uintptr_t>(dos.e_lfanew) + 4, &fh, sizeof(fh));
                                    if (sig == IMAGE_NT_SIGNATURE && (fh.Machine == 0x8664 || fh.Machine == 0x014C)) {
                                        is64 = (fh.Machine == 0x8664);
                                        uint32_t optOff = static_cast<uint32_t>(dos.e_lfanew) + 4u + static_cast<uint32_t>(sizeof(IMAGE_FILE_HEADER));
                                        uint32_t secOff = optOff + fh.SizeOfOptionalHeader;
                                        if (is64) {
                                            IMAGE_OPTIONAL_HEADER64 opt64{};
                                            ReadMem(hProc, baseAddr + optOff, &opt64, sizeof(opt64));
                                            impRva = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                                            impSz  = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                                        } else {
                                            IMAGE_OPTIONAL_HEADER32 opt32{};
                                            ReadMem(hProc, baseAddr + optOff, &opt32, sizeof(opt32));
                                            impRva = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                                            impSz  = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                                        }
                                        IMAGE_SECTION_HEADER chosenSec{};
                                        bool foundText = false;
                                        WORD maxSecs = std::min<WORD>(fh.NumberOfSections, 16);
                                        for (WORD s = 0; s < maxSecs; ++s) {
                                            IMAGE_SECTION_HEADER sec{};
                                            if (!ReadMem(hProc, baseAddr + secOff + s * sizeof(IMAGE_SECTION_HEADER), &sec, sizeof(sec))) {
                                                break;
                                            }
                                            if (s == 0 && !foundText) chosenSec = sec;
                                            if (std::strncmp(reinterpret_cast<const char*>(sec.Name), ".text", 5) == 0) {
                                                chosenSec = sec;
                                                foundText = true;
                                            } else if (std::strncmp(reinterpret_cast<const char*>(sec.Name), ".rdata", 6) == 0) {
                                                rdataRva = sec.VirtualAddress;
                                                rdataSz  = is64 ? sec.Misc.VirtualSize : sec.SizeOfRawData;
                                            }
                                        }
                                        textRva = chosenSec.VirtualAddress;
                                        textSz  = is64 ? chosenSec.Misc.VirtualSize : chosenSec.SizeOfRawData;
                                        if (textRva && textSz > 1024 * 1024) foundReady = true;
                                    }
                                }
                            }
                            if (!foundReady) {
                                CloseHandle(hProc);
                                hProc = NULL;
                            }
                        }
                    }
                }
                if (foundReady || aborted) break;
                Sleep(100);
            }

            if (!hProc) {
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                if (accessDeniedStreak >= 5 && lastOpenErr == ERROR_ACCESS_DENIED) {
                    ConPrint(TR("\n  [!] Access denied (Win32 Error 5) inspecting wotblitz.exe.\n",
                                "\n  [!] \xD0\x9E\xD1\x82\xD0\xBA\xD0\xB0\xD0\xB7\xD0\xB0\xD0\xBD\xD0\xBE \xD0\xB2 \xD0\xB4\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xB5 (\xD0\xBE\xD1\x88\xD0\xB8\xD0\xB1\xD0\xBA\xD0\xB0 Win32 5) \xD0\xBA \xD0\xBF\xD1\x80\xD0\xBE\xD1\x86\xD0\xB5\xD1\x81\xD1\x81\xD1\x83 wotblitz.exe.\n"));
                    ConPrint(TR("      Right-click CR1M Pro.exe and choose 'Run as administrator'.\n",
                                "      \xD0\x9D\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 \xD0\x9F\xD0\x9A\xD0\x9C \xD0\xBF\xD0\xBE CR1M Pro.exe -> \xC2\xAB\xD0\x97\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA \xD0\xBE\xD1\x82 \xD0\xB8\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB8 \xD0\xB0\xD0\xB4\xD0\xBC\xD0\xB8\xD0\xBD\xD0\xB8\xD1\x81\xD1\x82\xD1\x80\xD0\xB0\xD1\x82\xD0\xBE\xD1\x80\xD0\xB0\xC2\xBB.\n"));
                } else {
                    ConPrint(TR("\n  [!] Timed out waiting for initialized wotblitz.exe.\n",
                                "\n  [!] \xD0\x9F\xD1\x80\xD0\xB5\xD0\xB2\xD1\x8B\xD1\x88\xD0\xB5\xD0\xBD\xD0\xBE \xD0\xB2\xD1\x80\xD0\xB5\xD0\xBC\xD1\x8F \xD0\xBE\xD0\xB6\xD0\xB8\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD1\x8F \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA\xD0\xB0 wotblitz.exe.\n"));
                }
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                lastExitCode = 1;
                break;
            }

            sess = ModSessionState{};
            sess.hProc = hProc;
            sess.pid = pid;
            sess.baseAddr = baseAddr;
            sess.is64 = is64;

            // [5/5] Single read .text AOB scan + Patch + Verification
            ConPrint(TR("  [5/5] Engine & Precision Aim: Scanning ",
                        "  [5/5] \xD0\x9F\xD0\xB0\xD1\x82\xD1\x87\xD0\xB8 \xD0\xB4\xD0\xB2\xD0\xB8\xD0\xB6\xD0\xBA\xD0\xB0 \xD0\xB8 \xD0\xB0\xD0\xB8\xD0\xBC\xD0\xB0   : \xD0\x90\xD0\xBD\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xB7 ") +
                     (is64
                         ? TR("64-bit (MS Store)", "64-\xD0\xB1\xD0\xB8\xD1\x82 (MS Store)")
                         : TR("32-bit (Steam/WGC)", "32-\xD0\xB1\xD0\xB8\xD1\x82 (Steam/WGC)")) +
                     TR(" modules...\n", " \xD0\xBC\xD0\xBE\xD0\xB4\xD1\x83\xD0\xBB\xD0\xB5\xD0\xB9...\n"));

            report = PatchReport{};
            ApplySystemPerformanceOptimizations(hProc, pid, &sess);

            txtBuf.assign(textSz, 0);
            SIZE_T br = 0;
            if (!runtime::DynReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(baseAddr + textRva),
                                               txtBuf.data(), textSz, &br) ||
                br < textSz / 2) {
                CloseHandle(hProc);
                hProc = NULL;
                lastExitCode = 1;
                break;
            }
            rdata = RdataSlice{};
            if (rdataRva && rdataSz > 0 && rdataSz <= 32u * 1024u * 1024u) {
                rdata.rva = rdataRva;
                rdata.bytes.assign(rdataSz, 0);
                SIZE_T rbr = 0;
                if (!runtime::DynReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(baseAddr + rdataRva),
                                                   rdata.bytes.data(), rdataSz, &rbr) ||
                    rbr < rdataSz / 2) {
                    rdata = RdataSlice{};
                }
            }
            iat = ResolveKernel32Iat(hProc, baseAddr, is64, impRva, impSz);

            const RdataSlice* rdataPtr = rdata.bytes.empty() ? nullptr : &rdata;
            allOk = is64
                ? ApplyPatchesX64(hProc, baseAddr, txtBuf, textRva, iat,
                                  static_cast<uint32_t>(targetFps), report, *proof, &sess, rdataPtr, &LoadOrFetchSignedSigManifest)
                : ApplyPatchesX86(hProc, baseAddr, txtBuf, textRva, iat,
                                  static_cast<uint32_t>(targetFps), report, *proof, &sess, rdataPtr, &LoadOrFetchSignedSigManifest);

            // Safeguard: never consume Free Test Drive minutes if core FPS or Frame Pacer failed
            if (auth.trialActive && (!report.fpsCoreOk || !report.pacerOk)) {
                RevertModEffects(sess);
                trialGuardAborted = true;
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                ConPrint(TR("\n  [FAILED] This game update changed core engine signatures; Test Drive paused safely.\n",
                            "\n  [\xD0\x9E\xD0\xA8\xD0\x98\xD0\x91\xD0\x9A\xD0\x90] \xD0\x9E\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B \xD0\xB8\xD0\xB7\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xBB\xD0\xBE \xD1\x81\xD0\xB8\xD0\xB3\xD0\xBD\xD0\xB0\xD1\x82\xD1\x83\xD1\x80\xD1\x8B \xD0\xB4\xD0\xB2\xD0\xB8\xD0\xB6\xD0\xBA\xD0\xB0; \xD1\x82\xD0\xB5\xD1\x81\xD1\x82 \xD0\xB1\xD0\xB5\xD0\xB7\xD0\xBE\xD0\xBF\xD0\xB0\xD1\x81\xD0\xBD\xD0\xBE \xD0\xBE\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD.\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("  -> Trial Protection    : All temporary hooks reverted (0 minutes used).\n",
                            "  -> \xD0\x97\xD0\xB0\xD1\x89\xD0\xB8\xD1\x82\xD0\xB0 \xD1\x82\xD1\x80\xD0\xB8\xD0\xB0\xD0\xBB\xD0\xB0      : \xD0\x92\xD1\x81\xD0\xB5 \xD0\xB2\xD1\x80\xD0\xB5\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xBD\xD1\x8B\xD0\xB5 \xD0\xBF\xD0\xB0\xD1\x82\xD1\x87\xD0\xB8 \xD0\xBE\xD1\x82\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB5\xD0\xBD\xD1\x8B (0 \xD0\xBC\xD0\xB8\xD0\xBD\xD1\x83\xD1\x82 \xD0\xBF\xD0\xBE\xD1\x82\xD1\x80\xD0\xB0\xD1\x87\xD0\xB5\xD0\xBD\xD0\xBE).\n"));
                SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                if (!report.newerVersionAvailable.empty()) {
                    ConPrint(TR("  -> Update Available    : CR1M Pro Mod v",
                                "  -> \xD0\x94\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xBD\xD0\xBE \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 : CR1M Pro Mod v") +
                             report.newerVersionAvailable + "\n");
                }
                ConPrint(TR("  -> Check for updates   : https://cr1m.net/test-drive\n\n",
                            "  -> \xD0\x9F\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD0\xB8\xD1\x82\xD1\x8C \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD1\x8F : https://cr1m.net/test-drive\n\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                lastExitCode = 2;
                break;
            }

            if (allOk && report.failCount == 0) {
                SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("\n  [SUCCESS] All Engine, Frame Pacing, 1:1 Aim & Spotting optimizations active!\n",
                            "\n  [\xD0\xA3\xD0\xA1\xD0\x9F\xD0\x95\xD0\xA5] \xD0\x92\xD1\x81\xD0\xB5 \xD0\xBE\xD0\xBF\xD1\x82\xD0\xB8\xD0\xBC\xD0\xB8\xD0\xB7\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8 \xD0\xB4\xD0\xB2\xD0\xB8\xD0\xB6\xD0\xBA\xD0\xB0, \xD1\x84\xD1\x80\xD0\xB5\xD0\xB9\xD0\xBC\xD0\xBF\xD0\xB5\xD0\xB9\xD1\x81\xD0\xB8\xD0\xBD\xD0\xB3\xD0\xB0, \xD0\xB0\xD0\xB8\xD0\xBC\xD0\xB0 1:1 \xD0\xB8 \xD0\xB7\xD0\xB0\xD1\x81\xD0\xB2\xD0\xB5\xD1\x82\xD0\xB0 \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xBD\xD1\x8B!\n"));
            } else if (report.okCount > 0) {
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("\n  [PARTIAL] Some optimization modules were skipped on this game build.\n",
                            "\n  [\xD0\xA7\xD0\x90\xD0\xA1\xD0\xA2\xD0\x98\xD0\xA7\xD0\x9D\xD0\x9E] \xD0\xA7\xD0\xB0\xD1\x81\xD1\x82\xD1\x8C \xD0\xBC\xD0\xBE\xD0\xB4\xD1\x83\xD0\xBB\xD0\xB5\xD0\xB9 \xD0\xBE\xD0\xBF\xD1\x82\xD0\xB8\xD0\xBC\xD0\xB8\xD0\xB7\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8 \xD0\xBF\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x89\xD0\xB5\xD0\xBD\xD0\xB0 \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x8D\xD1\x82\xD0\xBE\xD0\xB9 \xD0\xB2\xD0\xB5\xD1\x80\xD1\x81\xD0\xB8\xD0\xB8 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B.\n"));
            } else {
                SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                ConPrint(TR("\n  [FAILED] Game engine updated and signatures did not match this build.\n",
                            "\n  [\xD0\x9E\xD0\xA8\xD0\x98\xD0\x91\xD0\x9A\xD0\x90] \xD0\x98\xD0\xB3\xD1\x80\xD0\xB0 \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xB8\xD0\xBB\xD0\xB0\xD1\x81\xD1\x8C, \xD0\xB8 \xD1\x81\xD0\xB8\xD0\xB3\xD0\xBD\xD0\xB0\xD1\x82\xD1\x83\xD1\x80\xD1\x8B \xD0\xBD\xD0\xB5 \xD1\x81\xD0\xBE\xD0\xB2\xD0\xBF\xD0\xB0\xD0\xBB\xD0\xB8 \xD1\x81 \xD1\x8D\xD1\x82\xD0\xBE\xD0\xB9 \xD1\x81\xD0\xB1\xD0\xBE\xD1\x80\xD0\xBA\xD0\xBE\xD0\xB9.\n"));
            }
            ConPrint(TR("  -> Client Edition      : ", "  -> \xD0\x92\xD0\xB5\xD1\x80\xD1\x81\xD0\xB8\xD1\x8F \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82\xD0\xB0      : ") +
                     launchedStore + " (" + (is64 ? std::string("x64") : std::string("x86 WOW64")) +
                     ", PID " + std::to_string(pid) + ")\n");
            if (report.fpsCoreOk && report.pacerOk) {
                ConPrint(TR("  -> Target Framerate    : ", "  -> \xD0\xA6\xD0\xB5\xD0\xBB\xD0\xB5\xD0\xB2\xD0\xBE\xD0\xB9 FPS         : ") +
                         std::to_string(targetFps) +
                         TR(" FPS (Precision Frame Pacer)\n",
                            " FPS (\xD1\x82\xD0\xBE\xD1\x87\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xBF\xD0\xB5\xD0\xB9\xD1\x81\xD0\xB5\xD1\x80 \xD0\xBA\xD0\xB0\xD0\xB4\xD1\x80\xD0\xBE\xD0\xB2)\n"));
            } else if (report.fpsCoreOk) {
                ConPrint(TR("  -> Target Framerate    : ", "  -> \xD0\xA6\xD0\xB5\xD0\xBB\xD0\xB5\xD0\xB2\xD0\xBE\xD0\xB9 FPS         : ") +
                         std::to_string(targetFps) +
                         TR(" FPS (Cap Unlocked; Frame Pacer Skipped)\n",
                            " FPS (\xD0\xBB\xD0\xB8\xD0\xBC\xD0\xB8\xD1\x82 \xD1\x81\xD0\xBD\xD1\x8F\xD1\x82; \xD0\xBF\xD0\xB5\xD0\xB9\xD1\x81\xD0\xB5\xD1\x80 \xD0\xBF\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x89\xD0\xB5\xD0\xBD)\n"));
            } else {
                ConPrint(TR("  -> Target Framerate    : Skipped on this game build\n",
                            "  -> \xD0\xA6\xD0\xB5\xD0\xBB\xD0\xB5\xD0\xB2\xD0\xBE\xD0\xB9 FPS         : \xD0\x9F\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x89\xD0\xB5\xD0\xBD \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x8D\xD1\x82\xD0\xBE\xD0\xB9 \xD0\xB2\xD0\xB5\xD1\x80\xD1\x81\xD0\xB8\xD0\xB8 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B\n"));
            }
            if (report.aimOk) {
                ConPrint(TR("  -> Precision Mouse Aim : 1:1 Linear Response Active\n",
                            "  -> \xD0\xA2\xD0\xBE\xD1\x87\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD1\x8C \xD0\xBC\xD1\x8B\xD1\x88\xD0\xB8 1:1   : \xD0\x9B\xD0\xB8\xD0\xBD\xD0\xB5\xD0\xB9\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xBE\xD1\x82\xD0\xBA\xD0\xBB\xD0\xB8\xD0\xBA 1:1 \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB5\xD0\xBD\n"));
            } else {
                ConPrint(TR("  -> Precision Mouse Aim : Skipped on this game build\n",
                            "  -> \xD0\xA2\xD0\xBE\xD1\x87\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD1\x8C \xD0\xBC\xD1\x8B\xD1\x88\xD0\xB8 1:1   : \xD0\x9F\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x89\xD0\xB5\xD0\xBD\xD0\xB0 \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x8D\xD1\x82\xD0\xBE\xD0\xB9 \xD0\xB2\xD0\xB5\xD1\x80\xD1\x81\xD0\xB8\xD0\xB8 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B\n"));
            }
            if (report.spottingOk) {
                ConPrint(TR("  -> Spotting Smoothness : Active (Stutter Reduction)\n",
                            "  -> \xD0\x9F\xD0\xBB\xD0\xB0\xD0\xB2\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD1\x8C \xD0\xB7\xD0\xB0\xD1\x81\xD0\xB2\xD0\xB5\xD1\x82\xD0\xB0   : \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xBD\xD0\xB0 (\xD1\x83\xD1\x81\xD1\x82\xD1\x80\xD0\xB0\xD0\xBD\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 \xD0\xBC\xD0\xB8\xD0\xBA\xD1\x80\xD0\xBE\xD1\x84\xD1\x80\xD0\xB8\xD0\xB7\xD0\xBE\xD0\xB2)\n"));
            } else {
                ConPrint(TR("  -> Spotting Smoothness : Skipped on this game build\n",
                            "  -> \xD0\x9F\xD0\xBB\xD0\xB0\xD0\xB2\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD1\x8C \xD0\xB7\xD0\xB0\xD1\x81\xD0\xB2\xD0\xB5\xD1\x82\xD0\xB0   : \xD0\x9F\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x89\xD0\xB5\xD0\xBD\xD0\xB0 \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x8D\xD1\x82\xD0\xBE\xD0\xB9 \xD0\xB2\xD0\xB5\xD1\x80\xD1\x81\xD0\xB8\xD0\xB8 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B\n"));
            }
            if (report.usedRemoteHotfix) {
                SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                ConPrint(TR("  -> Signature Hotfix    : Signed cr1m.net update applied automatically\n",
                            "  -> \xD0\xA5\xD0\xBE\xD1\x82\xD1\x84\xD0\xB8\xD0\xBA\xD1\x81 \xD1\x81\xD0\xB8\xD0\xB3\xD0\xBD\xD0\xB0\xD1\x82\xD1\x83\xD1\x80   : \xD0\x9F\xD0\xBE\xD0\xB4\xD0\xBF\xD0\xB8\xD1\x81\xD0\xB0\xD0\xBD\xD0\xBD\xD0\xBE\xD0\xB5 \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 cr1m.net \xD0\xBF\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB5\xD0\xBD\xD0\xBE\n"));
            }
            if (!allOk || report.failCount > 0 || !report.newerVersionAvailable.empty()) {
                SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                if (!report.newerVersionAvailable.empty()) {
                    ConPrint(TR("  -> Update Available    : CR1M Pro Mod v",
                                "  -> \xD0\x94\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xBD\xD0\xBE \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 : CR1M Pro Mod v") +
                             report.newerVersionAvailable + "\n");
                }
                ConPrint(TR("  -> Check for updates   : https://cr1m.net/test-drive\n",
                            "  -> \xD0\x9F\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD0\xB8\xD1\x82\xD1\x8C \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD1\x8F : https://cr1m.net/test-drive\n"));
            }
            ConPrint("\n");
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            lastExitCode = (allOk && report.failCount == 0) ? 0 : 2;

            // Steam only attach safeguard: never runs for WGC, MS Store, fresh Steam launch, or already modded Steam
            if (syncPass == 0 && launchedStore == "STEAM_ATTACHED" && sess.win10WasUnpatched) {
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("  [!] Steam Attach Note: Steam Blitz was already running before CR1M Pro Mod.\n",
                            "  [!] \xD0\x9F\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD1\x87\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 Steam: Blitz \xD0\xB1\xD1\x8B\xD0\xBB \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x89\xD0\xB5\xD0\xBD \xD0\xB4\xD0\xBE \xD0\xBE\xD1\x82\xD0\xBA\xD1\x80\xD1\x8B\xD1\x82\xD0\xB8\xD1\x8F CR1M Pro Mod.\n"));
                ConPrint(TR("      DX11 initialized before Flip flags; launching via CR1M Pro Mod guarantees Flip.\n",
                            "      DX11 \xD0\xB8\xD0\xBD\xD0\xB8\xD1\x86\xD0\xB8\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xB7\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBB\xD1\x81\xD1\x8F \xD0\xB4\xD0\xBE \xD1\x84\xD0\xBB\xD0\xB0\xD0\xB3\xD0\xBE\xD0\xB2 Flip; \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA \xD1\x87\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7 CR1M Pro Mod \xD0\xB3\xD0\xB0\xD1\x80\xD0\xB0\xD0\xBD\xD1\x82\xD0\xB8\xD1\x80\xD1\x83\xD0\xB5\xD1\x82 Flip.\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                if (!nonInteractive && !inv.steamExe.empty()) {
                    ConPrint(TR("  Relaunch Steam Blitz fresh via CR1M Pro Mod now? [R = Relaunch / ENTER = Keep Attached]: ",
                                "  \xD0\x9F\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD1\x8C Steam Blitz \xD1\x87\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7 CR1M Pro Mod \xD1\x81\xD0\xB5\xD0\xB9\xD1\x87\xD0\xB0\xD1\x81? [R = \xD0\x9F\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD1\x8C / ENTER = \xD0\x9F\xD1\x80\xD0\xBE\xD0\xB4\xD0\xBE\xD0\xBB\xD0\xB6\xD0\xB8\xD1\x82\xD1\x8C]: "));
                    std::string ans;
                    if (std::getline(std::cin, ans)) {
                        std::string t = Trim(ans);
                        std::string u = ToUpperAscii(t);
                        if (!u.empty() && (u[0] == 'R' || t.find("\xD0\x9A") == 0 || t.find("\xD0\xBA") == 0)) {
                            ConPrint(TR("\n  -> Relaunching Steam Blitz cleanly...\n\n",
                                        "\n  -> \xD0\xA7\xD0\xB8\xD1\x81\xD1\x82\xD1\x8B\xD0\xB9 \xD0\xBF\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA Steam Blitz...\n\n"));
                            ignorePid = pid;
                            TerminateAndRelaunchSteam(pid, hProc, inv);
                            pid = 0;
                            launchedStore = "STEAM";
                            continue;
                        }
                    }
                }
                ConPrint("\n");
            }
            break;
        }

        if (hProc && auth.trialActive && !trialGuardAborted) {
            const RdataSlice* rdataPtr = rdata.bytes.empty() ? nullptr : &rdata;
            RunLiveTrialWatchdog(auth, sess, *proof, txtBuf, textRva, iat,
                                 static_cast<uint32_t>(targetFps), nonInteractive, rdataPtr);
        }

        if (hProc) {
            CloseHandle(hProc);
            hProc = NULL;
        }

        if (nonInteractive || (auth.trialActive && !trialGuardAborted)) {
            break;
        }

        SignedReleaseManifest otaRel{};
        bool otaAvailable = TryConsumeVerifiedOtaUpdate(otaRel, (!allOk || report.failCount > 0) ? 400u : 0u);
        if (otaAvailable) {
            SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            ConPrint(TR("  -> OTA Update Ready    : CR1M Pro Mod v",
                        "  -> \xD0\x94\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xBD\xD0\xBE OTA \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 : CR1M Pro Mod v") +
                     otaRel.version +
                     TR(" (Press U + ENTER to install cleanly)\n\n",
                        " (\xD0\xBD\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 U + ENTER \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBA\xD0\xB8)\n\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        ClientInventory latestInv = DiscoverClients();
        bool wantExit = false;
        while (true) {
            if (otaAvailable) {
                ConPrint(TR("  Press ENTER to close, U to update, or press a letter (M / S / W) to launch a different client: ",
                            "  \xD0\x9D\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 ENTER \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xB2\xD1\x8B\xD1\x85\xD0\xBE\xD0\xB4\xD0\xB0, U \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xB8\xD1\x8F \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB1\xD1\x83\xD0\xBA\xD0\xB2\xD1\x83 (M / S / W) \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA\xD0\xB0 \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xBE\xD0\xB3\xD0\xBE \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82\xD0\xB0: "));
            } else {
                ConPrint(TR("  Press ENTER to close or press a letter (M / S / W) to launch a different client: ",
                            "  \xD0\x9D\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 ENTER \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xB2\xD1\x8B\xD1\x85\xD0\xBE\xD0\xB4\xD0\xB0 \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB2\xD0\xB2\xD0\xB5\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xB1\xD1\x83\xD0\xBA\xD0\xB2\xD1\x83 (M / S / W) \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA\xD0\xB0 \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xBE\xD0\xB3\xD0\xBE \xD0\xBA\xD0\xBB\xD0\xB8\xD0\xB5\xD0\xBD\xD1\x82\xD0\xB0: "));
            }
            std::string cmd;
            if (!std::getline(std::cin, cmd)) {
                wantExit = true;
                break;
            }
            std::string t = Trim(cmd);
            if (t.empty()) {
                wantExit = true;
                break;
            }
            std::string u = ToUpperAscii(t);
            bool pickM = (u[0] == 'M' || t.find("\xD0\xAC") == 0 || t.find("\xD1\x8C") == 0);
            bool pickS = (u[0] == 'S' || t.find("\xD0\xAB") == 0 || t.find("\xD1\x8B") == 0);
            bool pickW = (u[0] == 'W' || t.find("\xD0\xA6") == 0 || t.find("\xD1\x86") == 0);
            bool pickU = (u[0] == 'U' || t.find("\xD0\x93") == 0 || t.find("\xD0\xB3") == 0);
            if (pickU && otaAvailable) {
                if (PerformVerifiedOtaUpdate(otaRel)) {
                    lastExitCode = 0;
                    wantExit = true;
                    break;
                }
                continue;
            }
            if (pickM) {
                if (latestInv.hasMs) { nextSelectedStore = "MSSTORE"; ConPrint("\n"); break; }
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("  [!] Microsoft Store edition is not installed on this PC.\n",
                            "  [!] \xD0\x98\xD0\xB7\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 Microsoft Store \xD0\xBD\xD0\xB5 \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xBE \xD0\xBD\xD0\xB0 \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC \xD0\x9F\xD0\x9A.\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                continue;
            }
            if (pickS) {
                if (!latestInv.steamExe.empty() || latestInv.pidSteam) { nextSelectedStore = "STEAM"; ConPrint("\n"); break; }
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("  [!] Steam edition is not installed on this PC.\n",
                            "  [!] \xD0\x98\xD0\xB7\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 Steam \xD0\xBD\xD0\xB5 \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xBE \xD0\xBD\xD0\xB0 \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC \xD0\x9F\xD0\x9A.\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                continue;
            }
            if (pickW) {
                if (!latestInv.wgcExe.empty() || latestInv.pidWgc) { nextSelectedStore = "WGC"; ConPrint("\n"); break; }
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("  [!] Wargaming Game Center edition is not installed on this PC.\n",
                            "  [!] \xD0\x98\xD0\xB7\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 Wargaming Game Center \xD0\xBD\xD0\xB5 \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xBE \xD0\xBD\xD0\xB0 \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC \xD0\x9F\xD0\x9A.\n"));
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                continue;
            }
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("  [!] Invalid selection. Press ENTER to close or choose M, S, or W.\n",
                        "  [!] \xD0\x9D\xD0\xB5\xD0\xB2\xD0\xB5\xD1\x80\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xB2\xD1\x8B\xD0\xB1\xD0\xBE\xD1\x80. \xD0\x9D\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 ENTER \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB2\xD1\x8B\xD0\xB1\xD0\xB5\xD1\x80\xD0\xB8\xD1\x82\xD0\xB5 M, S \xD0\xB8\xD0\xBB\xD0\xB8 W.\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        if (wantExit) break;
    }

    proof->revoke();
    timeEndPeriod(1);
    return lastExitCode;
}
