// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/i18n.hpp"
#include "cr1m/util.hpp"
#include <cwctype>
#include <iostream>
#include <sstream>
#include <vector>

namespace cr1m {

namespace {

UiLang gLang = UiLang::EN;

bool IsCisPrimaryLangId(LANGID lid) {
    switch (PRIMARYLANGID(lid)) {
        case 0x19: // Russian
        case 0x22: // Ukrainian
        case 0x23: // Belarusian
        case 0x28: // Tajik
        case 0x3F: // Kazakh
        case 0x40: // Kyrgyz
        case 0x43: // Uzbek
            return true;
        default:
            return false;
    }
}

bool IsCisLocaleTag(std::wstring tag) {
    for (wchar_t& c : tag) c = static_cast<wchar_t>(towlower(c));
    static const wchar_t* kPrefixes[] = { L"ru", L"uk", L"be", L"kk", L"ky", L"uz", L"tg" };
    for (const wchar_t* p : kPrefixes) {
        size_t n = wcslen(p);
        if (tag.size() >= n && tag.compare(0, n, p) == 0 &&
            (tag.size() == n || tag[n] == L'-' || tag[n] == L'_')) {
            return true;
        }
    }
    static const wchar_t* kRegions[] = { L"-ru", L"-ua", L"-by", L"-kz", L"-kg", L"-uz", L"-tj" };
    for (const wchar_t* r : kRegions) {
        size_t pos = tag.find(r);
        if (pos != std::wstring::npos) {
            size_t end = pos + wcslen(r);
            if (end == tag.size() || tag[end] == L'-' || tag[end] == L'_') return true;
        }
    }
    return false;
}

std::string GetLanguagePrefPath() {
    return GetAppDataBaseDir() + "\\language.cfg";
}

std::string LoadSavedLangPref() {
    std::string text;
    if (!ReadFileUtf8W(Utf8ToWide(GetLanguagePrefPath()), text)) return "";
    std::istringstream iss(text);
    std::string line;
    std::getline(iss, line);
    std::string u = ToUpperAscii(Trim(line));
    if (u == "RU" || u == "EN") return u;
    return "";
}

void SaveLangPref(UiLang lang) {
    std::string base = GetAppDataBaseDir();
    CreateDirW(Utf8ToWide(base));
    WriteFileUtf8W(Utf8ToWide(GetLanguagePrefPath()), (lang == UiLang::RU ? "RU\n" : "EN\n"));
}

} // namespace

UiLang GetUiLang() { return gLang; }
void   SetUiLang(UiLang lang) { gLang = lang; }
bool   IsRu() { return gLang == UiLang::RU; }

bool IsInteractiveStdout() {
    static int cached = -1;
    if (cached < 0) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        cached = (h != INVALID_HANDLE_VALUE && h != NULL &&
                  GetFileType(h) == FILE_TYPE_CHAR && GetConsoleMode(h, &mode)) ? 1 : 0;
    }
    return cached == 1;
}

void ConPrint(const std::string& utf8) {
    if (utf8.empty()) return;
    if (IsInteractiveStdout()) {
        std::wstring w = Utf8ToWide(utf8);
        if (!w.empty()) {
            DWORD written = 0;
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), w.c_str(), static_cast<DWORD>(w.size()), &written, nullptr);
            return;
        }
    }
    std::cout << utf8 << std::flush;
}

void ConClearInteractiveScreen() {
    if (!IsInteractiveStdout()) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (!GetConsoleScreenBufferInfo(h, &csbi)) return;
    DWORD cells = static_cast<DWORD>(csbi.dwSize.X) * static_cast<DWORD>(csbi.dwSize.Y);
    COORD home{ 0, 0 };
    DWORD written = 0;
    FillConsoleOutputCharacterW(h, L' ', cells, home, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(h, home);
}

bool DetectRussianOsLocale() {
    if (IsCisPrimaryLangId(GetUserDefaultUILanguage())) return true;
    if (IsCisPrimaryLangId(GetSystemDefaultUILanguage())) return true;
    if (IsCisPrimaryLangId(LANGIDFROMLCID(GetUserDefaultLCID()))) return true;

    wchar_t locName[LOCALE_NAME_MAX_LENGTH]{};
    if (GetUserDefaultLocaleName(locName, LOCALE_NAME_MAX_LENGTH) > 0 && IsCisLocaleTag(locName)) {
        return true;
    }

    ULONG numLangs = 0, bufLen = 0;
    if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &numLangs, nullptr, &bufLen) && bufLen > 0) {
        std::vector<wchar_t> buf(bufLen, L'\0');
        if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &numLangs, buf.data(), &bufLen) && numLangs > 0) {
            if (IsCisLocaleTag(buf.data())) return true;
        }
    }
    return false;
}

void ResolveUiLanguage(const std::string& cfgLang,
                       const std::string& cliLang,
                       bool resetLang,
                       bool nonInteractive) {
    if (resetLang) {
        DeleteFileW(Utf8ToWide(GetLanguagePrefPath()).c_str());
    }
    if (cliLang == "RU") { gLang = UiLang::RU; return; }
    if (cliLang == "EN") { gLang = UiLang::EN; return; }
    if (cfgLang == "RU") { gLang = UiLang::RU; return; }
    if (cfgLang == "EN") { gLang = UiLang::EN; return; }

    std::string saved = LoadSavedLangPref();
    if (saved == "RU") { gLang = UiLang::RU; return; }
    if (saved == "EN") { gLang = UiLang::EN; return; }

    bool osRu = DetectRussianOsLocale();
    if (nonInteractive) {
        gLang = osRu ? UiLang::RU : UiLang::EN;
        return;
    }

    SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    ConPrint("============================================================================\n");
    ConPrint("                        CR1M Pro Mod  |  Language / \xD0\xAF\xD0\xB7\xD1\x8B\xD0\xBA\n");
    ConPrint("============================================================================\n\n");
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    ConPrint("  Choose preferred interface language / \xD0\x92\xD1\x8B\xD0\xB1\xD0\xB5\xD1\x80\xD0\xB8\xD1\x82\xD0\xB5 \xD1\x8F\xD0\xB7\xD1\x8B\xD0\xBA \xD0\xB8\xD0\xBD\xD1\x82\xD0\xB5\xD1\x80\xD1\x84\xD0\xB5\xD0\xB9\xD1\x81\xD0\xB0:\n\n");
    ConPrint("    [1] English\n");
    ConPrint("    [2] \xD0\xA0\xD1\x83\xD1\x81\xD1\x81\xD0\xBA\xD0\xB8\xD0\xB9  (RU / UA / BY / KZ)\n\n");
    ConPrint(std::string("  Detected PC Language / \xD0\xAF\xD0\xB7\xD1\x8B\xD0\xBA \xD0\x9F\xD0\x9A : ") +
             (osRu ? "\xD0\xA0\xD1\x83\xD1\x81\xD1\x81\xD0\xBA\xD0\xB8\xD0\xB9 (RU)" : "English (EN)") + "\n");
    ConPrint("  Asked once & saved / \xD0\xA1\xD0\xBF\xD1\x80\xD0\xB0\xD1\x88\xD0\xB8\xD0\xB2\xD0\xB0\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F \xD0\xBE\xD0\xB4\xD0\xB8\xD0\xBD \xD1\x80\xD0\xB0\xD0\xB7 \xD0\xB8 \xD1\x81\xD0\xBE\xD1\x85\xD1\x80\xD0\xB0\xD0\xBD\xD1\x8F\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F\n\n");
    ConPrint(std::string("  Select / \xD0\x92\xD1\x8B\xD0\xB1\xD0\xB5\xD1\x80\xD0\xB8\xD1\x82\xD0\xB5 [1/2] (ENTER = ") +
             (osRu ? "2 \xD0\xA0\xD1\x83\xD1\x81\xD1\x81\xD0\xBA\xD0\xB8\xD0\xB9" : "1 English") + "): ");

    std::string line;
    UiLang chosen = osRu ? UiLang::RU : UiLang::EN;
    if (std::getline(std::cin, line)) {
        std::string t = ToUpperAscii(Trim(line));
        if (!t.empty()) {
            if (t[0] == '1' || t[0] == 'E') chosen = UiLang::EN;
            else if (t[0] == '2' || t[0] == 'R') chosen = UiLang::RU;
            else if (t.find("\xD0\xA0") == 0 || t.find("\xD1\x80") == 0) chosen = UiLang::RU;
        }
    }
    gLang = chosen;
    SaveLangPref(chosen);
    ConClearInteractiveScreen();
}

} // namespace cr1m
