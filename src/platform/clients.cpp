// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/clients.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/util.hpp"
#include "cr1m/vrr.hpp"
#include "cr1m/win_runtime.hpp"
#include <shellapi.h>
#include <iostream>
#include <sstream>
#include <vector>

namespace cr1m {

namespace {

bool FileExistsW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
}

bool MatchesStorePath(DWORD pid, const std::string& storeFilter) {
    if (storeFilter == "AUTO" || storeFilter.empty()) return true;
    HANDLE hq = runtime::DynOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hq) return false;
    wchar_t wpath[MAX_PATH * 2]{};
    DWORD len = _countof(wpath);
    BOOL ok = runtime::DynQueryFullProcessImageNameW(hq, 0, wpath, &len);
    BOOL wow64 = FALSE;
    IsWow64Process(hq, &wow64);
    CloseHandle(hq);
    if (!ok) return false;
    std::string p = ToUpperAscii(WideToUtf8(wpath));
    bool isMs = (p.find("WINDOWSAPPS") != std::string::npos) ||
                (p.find("XBOXGAMES") != std::string::npos) ||
                (!wow64 && p.find("STEAMAPPS") == std::string::npos);
    bool isSt = (p.find("STEAMAPPS") != std::string::npos);
    if (storeFilter == "MSSTORE") return isMs;
    if (storeFilter == "STEAM") return isSt;
    if (storeFilter == "WGC") return !isMs && !isSt;
    return true;
}

bool IsMsStoreBlitzInstalled() {
    auto fn = runtime::Api().pGetPkgFam;
    if (!fn) return false;
    UINT32 count = 0, bufLen = 0;
    LONG r = fn(L"7458BE2C.546184C62B2A0_x4tje2y229k00", &count, nullptr, &bufLen, nullptr);
    return (r == ERROR_INSUFFICIENT_BUFFER && count > 0);
}

std::wstring FindSteamBlitzExe() {
    HKEY hk = NULL;
    std::wstring steamPath;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH]{}; DWORD cb = sizeof(buf) - sizeof(wchar_t);
        if (RegQueryValueExW(hk, L"SteamPath", NULL, NULL, reinterpret_cast<LPBYTE>(buf), &cb) == ERROR_SUCCESS) {
            steamPath = buf;
        }
        RegCloseKey(hk);
    }
    if (steamPath.empty()) return L"";
    for (wchar_t& ch : steamPath) if (ch == L'/') ch = L'\\';
    std::vector<std::wstring> libs = { steamPath };
    std::string vdfText;
    if (ReadFileUtf8W(steamPath + L"\\steamapps\\libraryfolders.vdf", vdfText)) {
        std::istringstream vdf(vdfText);
        std::string line;
        while (std::getline(vdf, line)) {
            size_t p = line.find("\"path\"");
            if (p != std::string::npos) {
                size_t q1 = line.find('"', p + 6);
                size_t q2 = (q1 != std::string::npos) ? line.find('"', q1 + 1) : std::string::npos;
                if (q1 != std::string::npos && q2 != std::string::npos) {
                    std::string raw = line.substr(q1 + 1, q2 - q1 - 1);
                    std::string unesc;
                    for (size_t i = 0; i < raw.size(); ++i) {
                        if (raw[i] == '\\' && i + 1 < raw.size() && raw[i + 1] == '\\') { unesc += '\\'; ++i; }
                        else unesc += raw[i];
                    }
                    libs.push_back(Utf8ToWide(unesc));
                }
            }
        }
    }
    const std::wstring suffix = L"\\steamapps\\common\\World of Tanks Blitz\\wotblitz.exe";
    for (const auto& lib : libs) {
        std::wstring candidate = lib + suffix;
        if (FileExistsW(candidate)) return candidate;
    }
    return L"";
}

std::wstring FindWgcBlitzExe() {
    const std::wstring common[4] = {
        L"C:\\Games\\World_of_Tanks_Blitz\\wotblitz.exe",
        L"D:\\Games\\World_of_Tanks_Blitz\\wotblitz.exe",
        L"C:\\Program Files (x86)\\World of Tanks Blitz\\wotblitz.exe",
        L"C:\\Program Files\\World of Tanks Blitz\\wotblitz.exe"
    };
    for (const auto& p : common) if (FileExistsW(p)) return p;

    const HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (HKEY root : roots) {
        HKEY hUn = NULL;
        if (RegOpenKeyExW(root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                          0, KEY_READ | KEY_WOW64_32KEY, &hUn) != ERROR_SUCCESS) continue;
        wchar_t keyName[256]{}; DWORD knLen = 255;
        for (DWORD idx = 0; RegEnumKeyExW(hUn, idx, keyName, &knLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
             ++idx, knLen = 255) {
            HKEY hApp = NULL;
            if (RegOpenKeyExW(hUn, keyName, 0, KEY_READ, &hApp) == ERROR_SUCCESS) {
                wchar_t loc[MAX_PATH]{}; DWORD lcb = sizeof(loc) - sizeof(wchar_t);
                if (RegQueryValueExW(hApp, L"InstallLocation", NULL, NULL, reinterpret_cast<LPBYTE>(loc), &lcb) == ERROR_SUCCESS) {
                    std::wstring exe = std::wstring(loc) + L"\\wotblitz.exe";
                    if (FileExistsW(exe)) { RegCloseKey(hApp); RegCloseKey(hUn); return exe; }
                }
                RegCloseKey(hApp);
            }
        }
        RegCloseKey(hUn);
    }
    return L"";
}

std::string FormatPidState(DWORD p) {
    return p ? (TR("RUNNING (PID ", "\xD0\x97\xD0\x90\xD0\x9F\xD0\xA3\xD0\xA9\xD0\x95\xD0\x9D (PID ") + std::to_string(p) + ")")
             : TR("Installed (Launch)", "\xD0\xA3\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD (\xD0\x97\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD1\x8C)");
}

} // namespace

DWORD FindWotbPid(const std::string& storeFilter, DWORD ignorePid) {
    HANDLE s = runtime::DynCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (runtime::DynProcess32FirstW(s, &pe)) {
        do {
            if (pe.th32ProcessID != ignorePid && _wcsicmp(pe.szExeFile, L"wotblitz.exe") == 0 &&
                MatchesStorePath(pe.th32ProcessID, storeFilter)) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (runtime::DynProcess32NextW(s, &pe));
    }
    CloseHandle(s);
    return pid;
}

ClientInventory DiscoverClients() {
    ClientInventory inv;
    inv.hasMs    = IsMsStoreBlitzInstalled();
    inv.steamExe = FindSteamBlitzExe();
    inv.wgcExe   = FindWgcBlitzExe();
    inv.pidMs    = FindWotbPid("MSSTORE");
    inv.pidSteam = FindWotbPid("STEAM");
    inv.pidWgc   = FindWotbPid("WGC");
    if (inv.pidMs) inv.hasMs = true;
    return inv;
}

bool LaunchSpecificStore(const std::string& store, const ClientInventory& inv) {
    if (store == "MSSTORE" && inv.hasMs) {
        ShellExecuteW(NULL, L"open", L"explorer.exe",
                      L"shell:AppsFolder\\7458BE2C.546184C62B2A0_x4tje2y229k00!Game", NULL, SW_SHOWNORMAL);
        return true;
    }
    if (store == "STEAM" && !inv.steamExe.empty()) {
        EnsureExeGpuPreferences(inv.steamExe);
        ShellExecuteW(NULL, L"open", L"steam://rungameid/444200", NULL, NULL, SW_SHOWNORMAL);
        return true;
    }
    if (store == "WGC" && !inv.wgcExe.empty()) {
        EnsureExeGpuPreferences(inv.wgcExe);
        std::wstring dir = inv.wgcExe.substr(0, inv.wgcExe.find_last_of(L"\\/"));
        ShellExecuteW(NULL, L"open", inv.wgcExe.c_str(), NULL, dir.c_str(), SW_SHOWNORMAL);
        return true;
    }
    return false;
}

std::string SelectTargetClient(const ModConfig& cfg, const ClientInventory& inv, bool nonInteractive) {
    if (cfg.store == "MSSTORE" || cfg.store == "STEAM" || cfg.store == "WGC") {
        return cfg.store;
    }

    int count = inv.availableCount();
    if (count == 0) return "";

    if (!nonInteractive && count > 1) {
        ConPrint(TR("\n  Multiple World of Tanks Blitz editions detected on this PC:\n",
                    "\n  \xD0\x9D\xD0\xB0 \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC \xD0\x9F\xD0\x9A \xD0\xBD\xD0\xB0\xD0\xB9\xD0\xB4\xD0\xB5\xD0\xBD\xD0\xBE \xD0\xBD\xD0\xB5\xD1\x81\xD0\xBA\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBA\xD0\xBE \xD0\xB8\xD0\xB7\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB9 World of Tanks Blitz:\n"));
        if (inv.hasMs) {
            ConPrint(TR("    [M] Microsoft Store / Xbox (64-bit) : ",
                        "    [M] Microsoft Store / Xbox (64-\xD0\xB1\xD0\xB8\xD1\x82) : ") + FormatPidState(inv.pidMs) + "\n");
        }
        if (!inv.steamExe.empty() || inv.pidSteam) {
            ConPrint(TR("    [S] Steam Edition (32-bit)            : ",
                        "    [S] Steam \xD0\x98\xD0\xB7\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 (32-\xD0\xB1\xD0\xB8\xD1\x82)          : ") + FormatPidState(inv.pidSteam) + "\n");
        }
        if (!inv.wgcExe.empty() || inv.pidWgc) {
            ConPrint(TR("    [W] Wargaming Game Center (32-bit)    : ",
                        "    [W] Wargaming Game Center (32-\xD0\xB1\xD0\xB8\xD1\x82)  : ") + FormatPidState(inv.pidWgc) + "\n");
        }

        while (true) {
            ConPrint(TR("\n  Press M (Microsoft Store), S (Steam), or W (WGC) and hit ENTER: ",
                        "\n  \xD0\x92\xD0\xB2\xD0\xB5\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 M (Microsoft Store), S (Steam) \xD0\xB8\xD0\xBB\xD0\xB8 W (WGC) \xD0\xB8 \xD0\xBD\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 ENTER: "));
            std::string choice;
            if (!std::getline(std::cin, choice)) break;
            std::string t = Trim(choice);
            std::string u = ToUpperAscii(t);
            if (!u.empty()) {
                bool pickM = (u[0] == 'M' || t.find("\xD0\xAC") == 0 || t.find("\xD1\x8C") == 0);
                bool pickS = (u[0] == 'S' || t.find("\xD0\xAB") == 0 || t.find("\xD1\x8B") == 0);
                bool pickW = (u[0] == 'W' || t.find("\xD0\xA6") == 0 || t.find("\xD1\x86") == 0);
                if (pickM && inv.hasMs) { ConPrint("\n"); return "MSSTORE"; }
                if (pickS && (!inv.steamExe.empty() || inv.pidSteam)) { ConPrint("\n"); return "STEAM"; }
                if (pickW && (!inv.wgcExe.empty() || inv.pidWgc)) { ConPrint("\n"); return "WGC"; }
            }
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("\n  [!] Invalid selection or edition not installed. Please choose an available letter.\n",
                        "\n  [!] \xD0\x9D\xD0\xB5\xD0\xB2\xD0\xB5\xD1\x80\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xB2\xD1\x8B\xD0\xB1\xD0\xBE\xD1\x80 \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB8\xD0\xB7\xD0\xB4\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5 \xD0\xBD\xD0\xB5 \xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xBB\xD0\xB5\xD0\xBD\xD0\xBE. \xD0\x92\xD1\x8B\xD0\xB1\xD0\xB5\xD1\x80\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xB4\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xBD\xD1\x83\xD1\x8E \xD0\xB1\xD1\x83\xD0\xBA\xD0\xB2\xD1\x83.\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    if (inv.pidMs) return "MSSTORE";
    if (inv.pidSteam) return "STEAM";
    if (inv.pidWgc) return "WGC";
    if (inv.hasMs) return "MSSTORE";
    if (!inv.steamExe.empty()) return "STEAM";
    if (!inv.wgcExe.empty()) return "WGC";
    return "";
}

void TerminateAndRelaunchSteam(DWORD oldPid, HANDLE& hProc, const ClientInventory& inv) {
    if (hProc) {
        CloseHandle(hProc);
        hProc = NULL;
    }
    if (oldPid != 0) {
        HANDLE hTerm = runtime::DynOpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, oldPid);
        if (hTerm) {
            TerminateProcess(hTerm, 0);
            WaitForSingleObject(hTerm, 5000);
            CloseHandle(hTerm);
        }
        for (int w = 0; w < 50; ++w) {
            if (FindWotbPid("STEAM") == 0) break;
            Sleep(100);
        }
        Sleep(800);
    }
    LaunchSpecificStore("STEAM", inv);
}

} // namespace cr1m
