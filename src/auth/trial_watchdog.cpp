// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/trial.hpp"
#include "cr1m/aob.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/patcher.hpp"
#include "cr1m/util.hpp"
#include "cr1m/win_runtime.hpp"
#include <mmsystem.h>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace cr1m {

namespace {

CRITICAL_SECTION gCtrlCs{};
bool             gCtrlCsInit = false;
ModSessionState* gWatchSess  = nullptr;
AuthSession*     gWatchAuth  = nullptr;
AuthProof*       gWatchProof = nullptr;
volatile bool    gWatchActive = false;
uint64_t         gWatchStartMs = 0;
LARGE_INTEGER    gWatchStartQpc{};
uint64_t         gWatchQpcFreq = 1;
uint64_t         gWatchStartWall = 0;
uint64_t         gWatchStartNet = 0;

} // namespace

void InitWatchdogCtrlLock() {
    if (!gCtrlCsInit) {
        InitializeCriticalSection(&gCtrlCs);
        gCtrlCsInit = true;
    }
}

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT ||
        ctrlType == CTRL_CLOSE_EVENT || ctrlType == CTRL_SHUTDOWN_EVENT) {
        if (gCtrlCsInit) EnterCriticalSection(&gCtrlCs);
        if (gWatchActive && gWatchSess && gWatchAuth) {
            uint64_t tickElapsed = (GetTickCount64() - gWatchStartMs) / 1000ULL;
            LARGE_INTEGER nowQpc{};
            QueryPerformanceCounter(&nowQpc);
            uint64_t qpcElapsed = (gWatchQpcFreq > 0 && nowQpc.QuadPart >= gWatchStartQpc.QuadPart)
                ? (static_cast<uint64_t>(nowQpc.QuadPart - gWatchStartQpc.QuadPart) / gWatchQpcFreq)
                : 0ULL;
            uint64_t curWall = GetUnixUtcSeconds();
            uint64_t wallElapsed = (gWatchStartWall > 0 && curWall >= gWatchStartWall) ? (curWall - gWatchStartWall) : 0ULL;
            uint64_t latestNet = ReadNetWallLatest();
            uint64_t netElapsed = (gWatchStartNet > 0 && latestNet >= gWatchStartNet) ? (latestNet - gWatchStartNet) : 0ULL;
            uint64_t elapsed = std::max<uint64_t>(std::max<uint64_t>(tickElapsed, qpcElapsed),
                                                  std::max<uint64_t>(wallElapsed, netElapsed));

            TrialPayload tp{};
            tp.magic        = TRIAL_PAYLOAD_MAGIC;
            tp.version      = 1;
            tp.usedSeconds  = std::min<uint64_t>(TRIAL_BUDGET_SECONDS, gWatchAuth->trialUsedSec + elapsed);
            tp.firstWallSec = gWatchAuth->firstWallSec;
            tp.maxWallSec   = std::max(gWatchAuth->maxWallSec, std::max(curWall, latestNet));
            tp.lastUpSec    = GetTickCount64() / 1000ULL;
            tp.flags        = (tp.usedSeconds >= TRIAL_BUDGET_SECONDS) ? 1u : 0u;
            SaveTrialAnchors(gWatchAuth->trialKeyId, tp);
            if (gWatchProof) gWatchProof->revoke();
            RevertModEffects(*gWatchSess);
            gWatchActive = false;
        }
        if (gCtrlCsInit) LeaveCriticalSection(&gCtrlCs);
        timeEndPeriod(1);
    }
    return FALSE;
}

void RunLiveTrialWatchdog(AuthSession& auth,
                          ModSessionState& sess,
                          AuthProof& proof,
                          const std::vector<uint8_t>& txtBuf,
                          uint32_t textRva,
                          const Kernel32Iat& iat,
                          uint32_t targetFps,
                          bool nonInteractive) {
    LARGE_INTEGER leaseQf{};
    QueryPerformanceFrequency(&leaseQf);
    uint64_t qpcFreq = (leaseQf.QuadPart > 0) ? static_cast<uint64_t>(leaseQf.QuadPart) : 1ULL;
    LARGE_INTEGER watchStartQpc{};
    QueryPerformanceCounter(&watchStartQpc);
    uint64_t watchStartWall = GetUnixUtcSeconds();
    uint64_t watchStartNet = ReadNetWallLatest();
    if (watchStartNet > watchStartWall) watchStartWall = watchStartNet;

    EnterCriticalSection(&gCtrlCs);
    gWatchSess      = &sess;
    gWatchAuth      = &auth;
    gWatchProof     = &proof;
    gWatchStartMs   = GetTickCount64();
    gWatchStartQpc  = watchStartQpc;
    gWatchQpcFreq   = qpcFreq;
    gWatchStartWall = watchStartWall;
    gWatchStartNet  = watchStartNet;
    gWatchActive    = true;
    LeaveCriticalSection(&gCtrlCs);

    uint64_t maxWallObs = std::max(auth.maxWallSec, watchStartWall);
    uint64_t lastSaveElapsed = 0;
    uint64_t lastLeaseElapsed = 0;
    uint64_t lastShownRem = UINT64_MAX;
    uint64_t netCheckTickCounter = 0;
    HANDLE hNetThread = NULL;
    bool expiredOrTampered = false;
    bool activateNow = false;
    std::string typedKeyBuf;
    std::string directSubmittedKey;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD timerOrigin{};
    bool hasTimerOrigin = false;

    while (true) {
        if (WaitForSingleObject(sess.hProc, 0) != WAIT_TIMEOUT) {
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            ConPrint(TR("\n\n  [!] Game process exited. Saving Test Drive progress...\n",
                        "\n\n  [!] \xD0\x9F\xD1\x80\xD0\xBE\xD1\x86\xD0\xB5\xD1\x81\xD1\x81 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B \xD0\xB7\xD0\xB0\xD0\xB2\xD0\xB5\xD1\x80\xD1\x88\xD1\x91\xD0\xBD. \xD0\xA1\xD0\xBE\xD1\x85\xD1\x80\xD0\xB0\xD0\xBD\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 \xD0\xBF\xD1\x80\xD0\xBE\xD0\xB3\xD1\x80\xD0\xB5\xD1\x81\xD1\x81\xD0\xB0 \xD1\x82\xD0\xB5\xD1\x81\xD1\x82-\xD0\xB4\xD1\x80\xD0\xB0\xD0\xB9\xD0\xB2\xD0\xB0...\n"));
            break;
        }

        uint64_t tickElapsed = (GetTickCount64() - gWatchStartMs) / 1000ULL;
        LARGE_INTEGER nowQpc{};
        QueryPerformanceCounter(&nowQpc);
        uint64_t qpcElapsed = (nowQpc.QuadPart >= watchStartQpc.QuadPart)
            ? (static_cast<uint64_t>(nowQpc.QuadPart - watchStartQpc.QuadPart) / qpcFreq)
            : 0ULL;

        uint64_t curWall = GetUnixUtcSeconds();
        if (curWall + 15 < maxWallObs) {
            expiredOrTampered = true;
            break;
        }
        if (curWall > maxWallObs) maxWallObs = curWall;
        uint64_t wallElapsed = (curWall >= watchStartWall) ? (curWall - watchStartWall) : 0ULL;

        if (++netCheckTickCounter % 480 == 0) {
            StartAsyncNetUtcCheck(hNetThread);
        }
        uint64_t latestNet = ReadNetWallLatest();
        if (latestNet > maxWallObs) maxWallObs = latestNet;
        if (latestNet > 0 && curWall + 60 < latestNet) {
            expiredOrTampered = true;
            break;
        }
        uint64_t netElapsed = (watchStartNet > 0 && latestNet >= watchStartNet) ? (latestNet - watchStartNet) : 0ULL;

        uint64_t elapsed = std::max<uint64_t>(std::max<uint64_t>(tickElapsed, qpcElapsed),
                                              std::max<uint64_t>(wallElapsed, netElapsed));
        uint64_t usedNow = auth.trialUsedSec + elapsed;

        if (usedNow >= TRIAL_BUDGET_SECONDS) {
            usedNow = TRIAL_BUDGET_SECONDS;
            expiredOrTampered = true;
            break;
        }

        uint64_t rem = TRIAL_BUDGET_SECONDS - usedNow;
        if (sess.caveBase && (elapsed >= lastLeaseElapsed + 1ULL || rem <= 12ULL)) {
            lastLeaseElapsed = elapsed;
            LARGE_INTEGER leaseQn{};
            QueryPerformanceCounter(&leaseQn);
            uint64_t leaseSec = std::min<uint64_t>(12ULL, rem + 1ULL);
            uint64_t leaseQpc = static_cast<uint64_t>(leaseQn.QuadPart) + leaseSec * static_cast<uint64_t>(leaseQf.QuadPart);
            SIZE_T bw = 0;
            runtime::DynWriteProcessMemory(sess.hProc, reinterpret_cast<LPVOID>(sess.caveBase + 0x50), &leaseQpc, 8, &bw);
        }

        if (elapsed >= lastSaveElapsed + 5ULL) {
            lastSaveElapsed = elapsed;
            TrialPayload tp{};
            tp.magic        = TRIAL_PAYLOAD_MAGIC;
            tp.version      = 1;
            tp.usedSeconds  = usedNow;
            tp.firstWallSec = auth.firstWallSec;
            tp.maxWallSec   = maxWallObs;
            tp.lastUpSec    = GetTickCount64() / 1000ULL;
            tp.flags        = 0;
            SaveTrialAnchors(auth.trialKeyId, tp);
        }

        if (rem != lastShownRem && typedKeyBuf.empty()) {
            std::ostringstream os;
            os << TR("  Time remaining for your trial : ", "  \xD0\x9E\xD1\x81\xD1\x82\xD0\xB0\xD0\xB2\xD1\x88\xD0\xB5\xD0\xB5\xD1\x81\xD1\x8F \xD0\xB2\xD1\x80\xD0\xB5\xD0\xBC\xD1\x8F \xD1\x82\xD0\xB5\xD1\x81\xD1\x82-\xD0\xB4\xD1\x80\xD0\xB0\xD0\xB9\xD0\xB2\xD0\xB0 : ")
               << std::setw(2) << std::setfill('0') << (rem / 60) << ":"
               << std::setw(2) << std::setfill('0') << (rem % 60)
               << TR(" OR enter your license key (from the website) to fully unlock",
                     " \xD0\x98\xD0\x9B\xD0\x98 \xD0\xB2\xD0\xB2\xD0\xB5\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 (\xD1\x81 \xD1\x81\xD0\xB0\xD0\xB9\xD1\x82\xD0\xB0) \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xBF\xD0\xBE\xD0\xBB\xD0\xBD\xD0\xBE\xD0\xB9 \xD1\x80\xD0\xB0\xD0\xB7\xD0\xB1\xD0\xBB\xD0\xBE\xD0\xBA\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xBA\xD0\xB8");
            std::string msg = os.str();

            if (IsInteractiveStdout()) {
                CONSOLE_SCREEN_BUFFER_INFO csbi{};
                if (!hasTimerOrigin && GetConsoleScreenBufferInfo(hOut, &csbi)) {
                    timerOrigin = csbi.dwCursorPosition;
                    hasTimerOrigin = true;
                } else if (hasTimerOrigin) {
                    SetConsoleCursorPosition(hOut, timerOrigin);
                }
                SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                ConPrint(msg + "   ");
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                if (lastShownRem == UINT64_MAX && hasTimerOrigin && GetConsoleScreenBufferInfo(hOut, &csbi)) {
                    SHORT cols = std::max<SHORT>(csbi.dwSize.X, 1);
                    size_t wlen = Utf8ToWide(msg).size() + 3;
                    SHORT rows = static_cast<SHORT>(wlen / static_cast<size_t>(cols));
                    if (timerOrigin.Y + rows >= csbi.dwSize.Y) {
                        timerOrigin.Y = std::max<SHORT>(0, static_cast<SHORT>(csbi.dwCursorPosition.Y - rows));
                    }
                }
            } else {
                SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                ConPrint("\r" + msg + "   ");
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            lastShownRem = rem;
        }

        if (!nonInteractive && hStdin != INVALID_HANDLE_VALUE) {
            DWORD evCount = 0;
            while (GetNumberOfConsoleInputEvents(hStdin, &evCount) && evCount > 0) {
                INPUT_RECORD ir{};
                DWORD rd = 0;
                if (!ReadConsoleInputW(hStdin, &ir, 1, &rd)) break;
                if (ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown) continue;
                wchar_t ch = ir.Event.KeyEvent.uChar.UnicodeChar;
                WORD vk = ir.Event.KeyEvent.wVirtualKeyCode;

                if (ch == L'\r' || ch == L'\n') {
                    if (!typedKeyBuf.empty()) {
                        std::string cand = StripWhitespace(typedKeyBuf);
                        if (cand.size() == 1 && (cand[0] == 'k' || cand[0] == 'K')) cand.clear();
                        directSubmittedKey = cand;
                    }
                    activateNow = true;
                    break;
                }
                if (vk == VK_ESCAPE) {
                    if (!typedKeyBuf.empty()) {
                        typedKeyBuf.clear();
                        ConPrint("\n");
                        hasTimerOrigin = false;
                        lastShownRem = UINT64_MAX;
                    }
                    continue;
                }
                if (ch == L'\b') {
                    if (!typedKeyBuf.empty()) {
                        typedKeyBuf.pop_back();
                        ConPrint("\b \b");
                        if (typedKeyBuf.empty()) {
                            ConPrint("\n");
                            hasTimerOrigin = false;
                            lastShownRem = UINT64_MAX;
                        }
                    }
                    continue;
                }
                bool morePrintable = false;
                {
                    INPUT_RECORD peekBuf[16]{};
                    DWORD peekN = 0;
                    if (PeekConsoleInputW(hStdin, peekBuf, 16, &peekN)) {
                        for (DWORD q = 0; q < peekN; ++q) {
                            if (peekBuf[q].EventType == KEY_EVENT &&
                                peekBuf[q].Event.KeyEvent.bKeyDown &&
                                peekBuf[q].Event.KeyEvent.uChar.UnicodeChar >= 0x20) {
                                morePrintable = true;
                                break;
                            }
                        }
                    }
                }
                if (typedKeyBuf.empty() && !morePrintable &&
                    (vk == 'K' || ch == L'k' || ch == L'K' || ch == L'\x041B' || ch == L'\x043B')) {
                    activateNow = true;
                    break;
                }
                if ((ch >= 0x20 && ch <= 0x7E) ||
                    (ch >= 0x2010 && ch <= 0x2015) || ch == 0x2212) {
                    char outCh = (ch >= 0x20 && ch <= 0x7E) ? static_cast<char>(ch) : '-';
                    if (typedKeyBuf.empty()) {
                        ConPrint(TR("\n\n  License Key: ", "\n\n  \xD0\x9A\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8: "));
                    }
                    typedKeyBuf.push_back(outCh);
                    ConPrint(std::string(1, outCh));
                }
            }
            if (activateNow) {
                FlushConsoleInputBuffer(hStdin);
                break;
            }
        }
        Sleep(250);
    }

    FinishAsyncNetUtcCheck(hNetThread);
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    EnterCriticalSection(&gCtrlCs);
    uint64_t finalTickElapsed = (GetTickCount64() - gWatchStartMs) / 1000ULL;
    LARGE_INTEGER finalQpc{};
    QueryPerformanceCounter(&finalQpc);
    uint64_t finalQpcElapsed = (finalQpc.QuadPart >= watchStartQpc.QuadPart)
        ? (static_cast<uint64_t>(finalQpc.QuadPart - watchStartQpc.QuadPart) / qpcFreq)
        : 0ULL;
    uint64_t finalWallNow = GetUnixUtcSeconds();
    uint64_t finalWallElapsed = (finalWallNow >= watchStartWall) ? (finalWallNow - watchStartWall) : 0ULL;
    uint64_t finalLatestNet = ReadNetWallLatest();
    if (finalLatestNet > maxWallObs) maxWallObs = finalLatestNet;
    uint64_t finalNetElapsed = (watchStartNet > 0 && finalLatestNet >= watchStartNet) ? (finalLatestNet - watchStartNet) : 0ULL;
    uint64_t finalElapsed = std::max<uint64_t>(std::max<uint64_t>(finalTickElapsed, finalQpcElapsed),
                                               std::max<uint64_t>(finalWallElapsed, finalNetElapsed));
    uint64_t finalUsed = expiredOrTampered
        ? TRIAL_BUDGET_SECONDS
        : std::min<uint64_t>(TRIAL_BUDGET_SECONDS, auth.trialUsedSec + finalElapsed);

    TrialPayload tp{};
    tp.magic        = TRIAL_PAYLOAD_MAGIC;
    tp.version      = 1;
    tp.usedSeconds  = finalUsed;
    tp.firstWallSec = auth.firstWallSec;
    tp.maxWallSec   = std::max(maxWallObs, finalWallNow);
    tp.lastUpSec    = GetTickCount64() / 1000ULL;
    tp.flags        = (expiredOrTampered || finalUsed >= TRIAL_BUDGET_SECONDS) ? 1u : 0u;
    SaveTrialAnchors(auth.trialKeyId, tp);

    if (expiredOrTampered) {
        proof.revoke();
        gWatchActive = false;
        RevertModEffects(sess);
    } else {
        gWatchActive = false;
    }
    gWatchSess  = nullptr;
    gWatchAuth  = nullptr;
    gWatchProof = nullptr;
    LeaveCriticalSection(&gCtrlCs);

    if (activateNow || expiredOrTampered) {
        if (expiredOrTampered) {
            Beep(750, 220);
            HWND hCon = GetConsoleWindow();
            if (hCon) { ShowWindow(hCon, SW_RESTORE); SetForegroundWindow(hCon); }
            SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            ConPrint(TR("\n\n  [!] 15-MINUTE TEST DRIVE ENDED - ALL MOD EFFECTS STOPPED IN RUNNING GAME.\n",
                        "\n\n  [!] 15-\xD0\x9C\xD0\x98\xD0\x9D\xD0\xA3\xD0\xA2\xD0\x9D\xD0\xAB\xD0\x99 \xD0\xA2\xD0\x95\xD0\xA1\xD0\xA2-\xD0\x94\xD0\xA0\xD0\x90\xD0\x99\xD0\x92 \xD0\x97\xD0\x90\xD0\x92\xD0\x95\xD0\xA0\xD0\xA8\xD0\x81\xD0\x9D \xE2\x80\x94 \xD0\x92\xD0\xA1\xD0\x95 \xD0\xAD\xD0\xA4\xD0\xA4\xD0\x95\xD0\x9A\xD0\xA2\xD0\xAB \xD0\x9E\xD0\xA2\xD0\x9A\xD0\x9B\xD0\xAE\xD0\xA7\xD0\x95\xD0\x9D\xD0\xAB \xD0\x92 \xD0\x98\xD0\x93\xD0\xA0\xD0\x95.\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        } else if (directSubmittedKey.empty()) {
            ConPrint(TR("\n\n  [*] LICENSE ACTIVATION (https://cr1m.net/test-drive)\n",
                        "\n\n  [*] \xD0\x90\xD0\x9A\xD0\xA2\xD0\x98\xD0\x92\xD0\x90\xD0\xA6\xD0\x98\xD0\xAF \xD0\x9B\xD0\x98\xD0\xA6\xD0\x95\xD0\x9D\xD0\x97\xD0\x98\xD0\x98 (https://cr1m.net/test-drive)\n"));
        } else {
            ConPrint("\n\n");
        }

        if (!nonInteractive) {
            bool gameAlive = (WaitForSingleObject(sess.hProc, 0) == WAIT_TIMEOUT);
            bool unlocked = false;
            std::string licDir = GetAppDataBaseDir();
            std::string licPath = licDir + "\\license.key";
            while (true) {
                std::string inKey;
                if (!directSubmittedKey.empty()) {
                    inKey = directSubmittedKey;
                    directSubmittedKey.clear();
                } else {
                    ConPrint(TR("  Paste your CR1M-XXXX-XXXX-XXXX License Key (or type EXIT): ",
                                "  \xD0\x92\xD1\x81\xD1\x82\xD0\xB0\xD0\xB2\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 CR1M-XXXX-XXXX-XXXX (\xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB2\xD0\xB2\xD0\xB5\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 EXIT): "));
                    if (!std::getline(std::cin, inKey)) break;
                }
                std::string trimmed = Trim(inKey);
                if (trimmed.empty()) continue;
                std::string up = ToUpperAscii(trimmed);
                if (up == "EXIT" || trimmed == "\xD0\x92\xD0\xAB\xD0\xA5\xD0\x9E\xD0\x94" ||
                    trimmed == "\xD0\xB2\xD1\x8B\xD1\x85\xD0\xBE\xD0\xB4") break;

                std::string normKey = NormalizeLicenseKeyPaste(trimmed);
                if (!IsValidLicenseKeyFormat(normKey)) {
                    PrintActivationError(ActivateStatus::InvalidFormat);
                    continue;
                }
                if (!ConfirmSpooferBeforeBind(auth.hb, nonInteractive)) continue;

                ConPrint(TR("  [*] Activating license key online...\n",
                            "  [*] \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB0 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBE\xD0\xBD\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD...\n"));
                std::string activeKey;
                std::optional<AuthProof> newProof;
                ActivateStatus st = ActivateLicenseKeyOnline(auth.hb, normKey, licDir, licPath, activeKey, newProof);
                if (st == ActivateStatus::Ok && newProof) {
                    proof = std::move(*newProof);
                    unlocked = true;
                    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    ConPrint(TR("  [OK] License activated & bound to this PC (",
                                "  [OK] \xD0\x9B\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD1\x8F \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xB8 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB7\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xBA \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC\xD1\x83 \xD0\x9F\xD0\x9A (") +
                             MaskLicenseKeyForDisplay(activeKey) + ")!\n");
                    if (gameAlive && WaitForSingleObject(sess.hProc, 0) == WAIT_TIMEOUT) {
                        if (!expiredOrTampered) {
                            if (sess.caveBase) {
                                uint64_t zeroLease = 0ULL;
                                SIZE_T bw = 0;
                                runtime::DynWriteProcessMemory(sess.hProc, reinterpret_cast<LPVOID>(sess.caveBase + 0x50), &zeroLease, 8, &bw);
                                FlushInstructionCache(sess.hProc, reinterpret_cast<LPCVOID>(sess.caveBase), 0x60);
                            }
                            ConPrint(TR("  [OK] Upgraded live to Unlimited License (zero frame interruption).\n",
                                        "  [OK] \xD0\x91\xD0\xB5\xD0\xB7\xD0\xBB\xD0\xB8\xD0\xBC\xD0\xB8\xD1\x82\xD0\xBD\xD0\xB0\xD1\x8F \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD1\x8F \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xBD\xD0\xB0 \xD0\xBB\xD0\xB5\xD1\x82\xD1\x83 (\xD0\xB1\xD0\xB5\xD0\xB7 \xD1\x80\xD0\xB0\xD0\xB7\xD1\x80\xD1\x8B\xD0\xB2\xD0\xB0 \xD0\xBA\xD0\xB0\xD0\xB4\xD1\x80\xD0\xBE\xD0\xB2).\n"));
                        } else {
                            ApplySystemPerformanceOptimizations(sess.hProc, sess.pid, &sess);
                            int ok2 = 0, fail2 = 0;
                            bool reok = sess.is64
                                ? ApplyPatchesX64(sess.hProc, sess.baseAddr, txtBuf, textRva, iat, targetFps, ok2, fail2, proof, &sess)
                                : ApplyPatchesX86(sess.hProc, sess.baseAddr, txtBuf, textRva, iat, targetFps, ok2, fail2, proof, &sess);
                            ConPrint(TR("  [OK] Live Re-Apply: ", "  [OK] \xD0\x9F\xD0\xBE\xD0\xB2\xD1\x82\xD0\xBE\xD1\x80\xD0\xBD\xD0\xBE\xD0\xB5 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5: ") +
                                     (reok ? TR("SUCCESS", "\xD0\xA3\xD0\xA1\xD0\x9F\xD0\x95\xD0\xA5") : TR("PARTIAL", "\xD0\xA7\xD0\x90\xD0\xA1\xD0\xA2\xD0\x98\xD0\xA7\xD0\x9D\xD0\x9E")) + "\n");
                        }
                    }
                    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    break;
                }
                PrintActivationError(st);
            }
            if (!unlocked && !expiredOrTampered) {
                RevertModEffects(sess);
            }
        }
    }
}

} // namespace cr1m
