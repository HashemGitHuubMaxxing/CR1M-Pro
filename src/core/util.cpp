// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/util.hpp"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace cr1m {

void WipeStr(std::string& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size());
    s.clear();
}

void WipeWStr(std::wstring& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
}

std::string StripWhitespace(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (i + 2 < s.size() && c == 0xEF && static_cast<unsigned char>(s[i + 1]) == 0xBB &&
            static_cast<unsigned char>(s[i + 2]) == 0xBF) {
            i += 3;
            continue;
        }
        if (i + 2 < s.size() && c == 0xE2 && static_cast<unsigned char>(s[i + 1]) == 0x80 &&
            (static_cast<unsigned char>(s[i + 2]) == 0x8B || static_cast<unsigned char>(s[i + 2]) == 0x8C ||
             static_cast<unsigned char>(s[i + 2]) == 0x8D)) {
            i += 3;
            continue;
        }
        if (i + 1 < s.size() && c == 0xC2 && static_cast<unsigned char>(s[i + 1]) == 0xA0) {
            i += 2;
            continue;
        }
        if (c <= 0x20 || std::isspace(c)) {
            ++i;
            continue;
        }
        out += static_cast<char>(c);
        ++i;
    }
    return out;
}

std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b) {
        if (a + 2 < b && static_cast<unsigned char>(s[a]) == 0xEF &&
            static_cast<unsigned char>(s[a + 1]) == 0xBB &&
            static_cast<unsigned char>(s[a + 2]) == 0xBF) {
            a += 3;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(s[a])) || static_cast<unsigned char>(s[a]) <= 0x1F) {
            ++a;
            continue;
        }
        break;
    }
    while (b > a && (std::isspace(static_cast<unsigned char>(s[b - 1])) ||
                     static_cast<unsigned char>(s[b - 1]) <= 0x1F)) {
        --b;
    }
    return s.substr(a, b - a);
}

std::string ToUpperAscii(std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? static_cast<size_t>(n) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n > 0 ? static_cast<size_t>(n) : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string GetEnvVarUtf8(const std::string& name) {
    std::wstring wn = Utf8ToWide(name);
    DWORD need = GetEnvironmentVariableW(wn.c_str(), NULL, 0);
    if (need == 0) return "";
    std::vector<wchar_t> buf(need + 1, L'\0');
    DWORD n = GetEnvironmentVariableW(wn.c_str(), buf.data(), need);
    if (n == 0 || n >= need) return "";
    return WideToUtf8(std::wstring(buf.data(), n));
}

void CreateDirW(const std::wstring& dir) {
    if (dir.empty()) return;
    if (CreateDirectoryW(dir.c_str(), NULL)) return;
    DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS) return;
    if (err == ERROR_PATH_NOT_FOUND) {
        size_t pos = dir.find_last_of(L"\\/");
        if (pos != std::wstring::npos && pos > 2) {
            CreateDirW(dir.substr(0, pos));
            CreateDirectoryW(dir.c_str(), NULL);
        }
    }
}

bool ReadFileUtf8W(const std::wstring& path, std::string& out) {
    out.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > (16LL * 1024 * 1024)) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    size_t total = 0;
    while (total < out.size()) {
        DWORD chunk = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - total, 1024 * 1024));
        if (!ReadFile(h, &out[total], want, &chunk, NULL) || chunk == 0) break;
        total += chunk;
    }
    CloseHandle(h);
    out.resize(total);
    if (out.size() >= 3 && static_cast<unsigned char>(out[0]) == 0xEF &&
        static_cast<unsigned char>(out[1]) == 0xBB && static_cast<unsigned char>(out[2]) == 0xBF) {
        out.erase(0, 3);
    }
    return true;
}

bool WriteFileUtf8W(const std::wstring& path, const std::string& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t total = 0;
    bool ok = true;
    while (total < data.size()) {
        DWORD wr = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(data.size() - total, 1024 * 1024));
        if (!WriteFile(h, data.data() + total, want, &wr, NULL) || wr == 0) {
            ok = false;
            break;
        }
        total += wr;
    }
    CloseHandle(h);
    return ok && total == data.size();
}

bool ReadFileBytes(const std::string& path, std::vector<uint8_t>& out, bool& exists) {
    exists = false;
    out.clear();
    std::wstring wp = Utf8ToWide(path);
    DWORD attr = GetFileAttributesW(wp.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    exists = true;
    HANDLE h = CreateFileW(wp.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > (16LL * 1024 * 1024)) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    size_t total = 0;
    while (total < out.size()) {
        DWORD chunk = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(out.size() - total, 1024 * 1024));
        if (!ReadFile(h, &out[total], want, &chunk, NULL) || chunk == 0) break;
        total += chunk;
    }
    CloseHandle(h);
    out.resize(total);
    return total == static_cast<size_t>(sz.QuadPart);
}

void WriteFileBytesHidden(const std::string& dir, const std::string& path, const void* data, size_t len) {
    std::wstring wDir = Utf8ToWide(dir);
    std::wstring wPath = Utf8ToWide(path);
    CreateDirW(wDir);
    SetFileAttributesW(wPath.c_str(), FILE_ATTRIBUTE_NORMAL);
    HANDLE h = CreateFileW(wPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        size_t total = 0;
        const BYTE* p = static_cast<const BYTE*>(data);
        while (total < len) {
            DWORD wr = 0;
            DWORD want = static_cast<DWORD>(std::min<size_t>(len - total, 1024 * 1024));
            if (!WriteFile(h, p + total, want, &wr, NULL) || wr == 0) break;
            total += wr;
        }
        CloseHandle(h);
        SetFileAttributesW(wPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }
}

bool SaveLicenseKeyAtomic(const std::string& licDir, const std::string& licPath, const std::string& content) {
    CreateDirW(Utf8ToWide(licDir));
    std::string tmpPath = licPath + ".tmp";
    std::wstring wTmp = Utf8ToWide(tmpPath);
    std::wstring wDst = Utf8ToWide(licPath);
    if (WriteFileUtf8W(wTmp, content)) {
        if (MoveFileExW(wTmp.c_str(), wDst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            return true;
        }
        DeleteFileW(wTmp.c_str());
    }
    return WriteFileUtf8W(wDst, content);
}

std::string CleanKeyPaste(const std::string& raw) {
    std::string s = StripWhitespace(raw);
    auto stripUtf8Wrap = [&]() -> bool {
        if (s.size() >= 3) {
            const unsigned char* b = reinterpret_cast<const unsigned char*>(s.data());
            if (b[0] == 0xE2 && b[1] == 0x80 && (b[2] >= 0x98 && b[2] <= 0x9D)) { s.erase(0, 3); return true; }
            size_t n = s.size();
            if (b[n - 3] == 0xE2 && b[n - 2] == 0x80 && (b[n - 1] >= 0x98 && b[n - 1] <= 0x9D)) { s.erase(n - 3, 3); return true; }
        }
        if (s.size() >= 2) {
            const unsigned char* b = reinterpret_cast<const unsigned char*>(s.data());
            if (b[0] == 0xC2 && (b[1] == 0xAB || b[1] == 0xBB)) { s.erase(0, 2); return true; }
            size_t n = s.size();
            if (b[n - 2] == 0xC2 && (b[n - 1] == 0xAB || b[n - 1] == 0xBB)) { s.erase(n - 2, 2); return true; }
        }
        return false;
    };
    auto isAsciiWrap = [](char c) -> bool {
        return c == '"' || c == '\'' || c == '`' || c == '<' || c == '>' ||
               c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}' ||
               c == ',' || c == '.' || c == ';' || c == ':';
    };
    bool changed = true;
    while (changed && !s.empty()) {
        changed = stripUtf8Wrap();
        while (!s.empty() && isAsciiWrap(s.front())) { s.erase(s.begin()); changed = true; }
        while (!s.empty() && isAsciiWrap(s.back()))  { s.pop_back(); changed = true; }
    }
    return StripWhitespace(s);
}

std::string GetAppDataBaseDir() {
    std::string appData = GetEnvVarUtf8("APPDATA");
    return appData + "\\CR1M_Pro_Mod";
}

std::string GetLocalAppDataDirA() {
    std::string la = GetEnvVarUtf8("LOCALAPPDATA");
    return !la.empty() ? la : GetAppDataBaseDir();
}

std::string GetProgramDataBaseDir() {
    std::string pd = GetEnvVarUtf8("ProgramData");
    return !pd.empty() ? (pd + "\\CR1M_PublicData") : std::string("");
}

std::string GetPublicDocsDirA() {
    std::string pub = GetEnvVarUtf8("PUBLIC");
    return !pub.empty() ? (pub + "\\Documents") : std::string("");
}

void ShredAndDeleteFileW(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return;
    uint64_t sz = (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
    if (sz > 0 && sz <= 16ULL * 1024ULL * 1024ULL) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            uint8_t zeros[4096]{};
            uint64_t rem = sz;
            while (rem > 0) {
                DWORD chunk = static_cast<DWORD>(rem > sizeof(zeros) ? sizeof(zeros) : rem);
                DWORD wr = 0;
                if (!WriteFile(h, zeros, chunk, &wr, NULL) || wr == 0) break;
                rem -= wr;
            }
            FlushFileBuffers(h);
            CloseHandle(h);
        }
    }
    DeleteFileW(path.c_str());
}

void PurgeLegacyDebugLogs() {
    std::string base = GetAppDataBaseDir();
    if (base.empty()) return;
    std::string logsDir = base + "\\logs";
    std::string logFile = logsDir + "\\cr1m_debug.log";
    std::string oldFile = logFile + ".old";
    ShredAndDeleteFileW(Utf8ToWide(logFile));
    ShredAndDeleteFileW(Utf8ToWide(oldFile));
    RemoveDirectoryW(Utf8ToWide(logsDir).c_str());
}

void SetColor(WORD attr) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}

std::string BytesToLowerHex(const BYTE* b, size_t n) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[(b[i] >> 4) & 0x0F]);
        out.push_back(kHex[b[i] & 0x0F]);
    }
    return out;
}

std::string BytesToUpperHex(const BYTE* b, size_t n) {
    std::ostringstream os;
    for (size_t i = 0; i < n; ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << static_cast<int>(b[i]);
    }
    return os.str();
}

bool HexDecode(const std::string& hex, std::vector<BYTE>& out) {
    out.clear();
    if (hex.empty() || (hex.size() & 1u) != 0) return false;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<BYTE>((hi << 4) | lo));
    }
    return true;
}

bool CtEqualStr(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool IsValidLicenseKeyChar(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '9');
}

bool IsValidLicenseKeyFormat(const std::string& key) {
    if (key.size() != 19) return false;
    if (key[0] != 'C' || key[1] != 'R' || key[2] != '1' || key[3] != 'M' || key[4] != '-') return false;
    if (key[9] != '-' || key[14] != '-') return false;
    for (size_t i = 5; i < 19; ++i) {
        if (i == 9 || i == 14) continue;
        if (!IsValidLicenseKeyChar(key[i])) return false;
    }
    return true;
}

std::string NormalizeLicenseKeyPaste(const std::string& raw) {
    std::string norm;
    norm.reserve(raw.size());
    for (size_t i = 0; i < raw.size();) {
        unsigned char c = static_cast<unsigned char>(raw[i]);
        if (i + 2 < raw.size() && c == 0xE2 && static_cast<unsigned char>(raw[i + 1]) == 0x80 &&
            (static_cast<unsigned char>(raw[i + 2]) >= 0x90 && static_cast<unsigned char>(raw[i + 2]) <= 0x94)) {
            norm.push_back('-');
            i += 3;
            continue;
        }
        if (i + 2 < raw.size() && c == 0xE2 && static_cast<unsigned char>(raw[i + 1]) == 0x88 &&
            static_cast<unsigned char>(raw[i + 2]) == 0x92) {
            norm.push_back('-');
            i += 3;
            continue;
        }
        norm.push_back(static_cast<char>(c));
        ++i;
    }

    std::string cleaned = ToUpperAscii(CleanKeyPaste(norm));
    if (IsValidLicenseKeyFormat(cleaned)) return cleaned;

    std::string upperRaw = ToUpperAscii(norm);
    for (size_t pos = 0; pos + 19 <= upperRaw.size(); ++pos) {
        if (upperRaw[pos] == 'C' && upperRaw[pos + 1] == 'R' &&
            upperRaw[pos + 2] == '1' && upperRaw[pos + 3] == 'M' && upperRaw[pos + 4] == '-') {
            std::string cand = upperRaw.substr(pos, 19);
            if (IsValidLicenseKeyFormat(cand)) return cand;
        }
    }
    return cleaned;
}

std::string MaskLicenseKeyForDisplay(const std::string& key) {
    if (key.size() == 19) {
        return key.substr(0, 10) + "****" + key.substr(14);
    }
    return "CR1M-****";
}

bool JsonFindValueStart(const std::string& json, const std::string& key, size_t& outPos) {
    const size_t n = json.size();
    size_t i = 0;
    while (i < n && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n')) ++i;
    if (i >= n || json[i] != '{') return false;
    ++i;
    while (i < n) {
        while (i < n && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n' || json[i] == ',')) ++i;
        if (i >= n || json[i] == '}') return false;
        if (json[i] != '"') return false;
        size_t keyStart = i + 1;
        size_t j = keyStart;
        while (j < n) {
            if (json[j] == '\\' && j + 1 < n) { j += 2; continue; }
            if (json[j] == '"') break;
            ++j;
        }
        if (j >= n) return false;
        std::string foundKey = json.substr(keyStart, j - keyStart);
        i = j + 1;
        while (i < n && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n')) ++i;
        if (i >= n || json[i] != ':') return false;
        ++i;
        while (i < n && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n')) ++i;
        if (i >= n) return false;
        if (foundKey == key) {
            outPos = i;
            return true;
        }
        if (json[i] == '"') {
            ++i;
            while (i < n) {
                if (json[i] == '\\' && i + 1 < n) { i += 2; continue; }
                if (json[i] == '"') { ++i; break; }
                ++i;
            }
        } else if (json[i] == '{' || json[i] == '[') {
            int depth = 0;
            bool inS = false;
            while (i < n) {
                char c = json[i++];
                if (inS) {
                    if (c == '\\' && i < n) { ++i; continue; }
                    if (c == '"') inS = false;
                } else {
                    if (c == '"') inS = true;
                    else if (c == '{' || c == '[') ++depth;
                    else if (c == '}' || c == ']') { if (--depth == 0) break; }
                }
            }
        } else {
            while (i < n && json[i] != ',' && json[i] != '}') ++i;
        }
    }
    return false;
}

bool JsonExtractStringField(const std::string& json, const std::string& key, std::string& outVal) {
    outVal.clear();
    size_t pos = 0;
    if (!JsonFindValueStart(json, key, pos)) return false;
    if (pos >= json.size() || json[pos] != '"') return false;
    ++pos;
    while (pos < json.size()) {
        char c = json[pos++];
        if (c == '"') return true;
        if (c == '\\' && pos < json.size()) {
            char esc = json[pos++];
            if (esc == '"' || esc == '\\' || esc == '/') outVal.push_back(esc);
            else if (esc == 'n') outVal.push_back('\n');
            else if (esc == 'r') outVal.push_back('\r');
            else if (esc == 't') outVal.push_back('\t');
            else outVal.push_back(esc);
        } else {
            outVal.push_back(c);
        }
    }
    outVal.clear();
    return false;
}

bool JsonExtractBoolField(const std::string& json, const std::string& key, bool& outVal) {
    outVal = false;
    size_t pos = 0;
    if (!JsonFindValueStart(json, key, pos)) return false;
    auto isTerm = [&](size_t idx) -> bool {
        if (idx >= json.size()) return true;
        char c = json[idx];
        return c == ',' || c == '}' || c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    if (pos + 4 <= json.size() && json.compare(pos, 4, "true") == 0 && isTerm(pos + 4)) {
        outVal = true;
        return true;
    }
    if (pos + 5 <= json.size() && json.compare(pos, 5, "false") == 0 && isTerm(pos + 5)) {
        outVal = false;
        return true;
    }
    return false;
}

} // namespace cr1m
