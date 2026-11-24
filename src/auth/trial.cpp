// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/trial.hpp"
#include "cr1m/util.hpp"
#include <winhttp.h>
#include <algorithm>
#include <cstring>

namespace cr1m {

namespace {

volatile LONG64 gNetWallLatest = 0;
volatile LONG   gNetThreadRunning = 0;

DWORD WINAPI NetUtcCheckThreadProc(LPVOID) {
    uint64_t t = QueryNetUtcSeconds();
    if (t > 0) {
        InterlockedExchange64(&gNetWallLatest, static_cast<LONG64>(t));
    }
    InterlockedExchange(&gNetThreadRunning, 0);
    return 0;
}

bool DeriveTrialKey(const std::string& hwid, BYTE outKey[32]) {
    BCRYPT_ALG_HANDLE hSha = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        return false;
    }
    std::string mat = "CR1M_TD_PUB_SALT_2026#S1|" + hwid;
    bool ok = ComputeSha256(hSha, mat.data(), mat.size(), outKey);
    WipeStr(mat);
    BCryptCloseAlgorithmProvider(hSha, 0);
    return ok;
}

bool SealTrialBlob(const std::string& hwid, const TrialPayload& pl, TrialDiskBlob& outBlob) {
    BYTE key[32]{};
    if (!DeriveTrialKey(hwid, key)) return false;
    BCRYPT_ALG_HANDLE hSha = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        SecureZeroMemory(key, sizeof(key));
        return false;
    }

    outBlob.hdrMagic = TRIAL_BLOB_HDR_MAGIC;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, outBlob.nonce, sizeof(outBlob.nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        uint64_t tc = GetTickCount64() ^ __rdtsc();
        memcpy(outBlob.nonce, &tc, 8);
    }

    BYTE streamInput[40]{};
    memcpy(streamInput, key, 32);
    memcpy(streamInput + 32, outBlob.nonce, 8);
    BYTE streamA[32]{}, streamB[32]{};
    ComputeSha256(hSha, streamInput, sizeof(streamInput), streamA);
    streamInput[32] ^= 0xA5;
    ComputeSha256(hSha, streamInput, sizeof(streamInput), streamB);
    SecureZeroMemory(streamInput, sizeof(streamInput));

    const uint8_t* raw = reinterpret_cast<const uint8_t*>(&pl);
    for (size_t i = 0; i < sizeof(TrialPayload); ++i) {
        uint8_t kbyte = (i < 32) ? streamA[i] : streamB[i - 32];
        outBlob.cipher[i] = raw[i] ^ kbyte;
    }
    SecureZeroMemory(streamA, sizeof(streamA));
    SecureZeroMemory(streamB, sizeof(streamB));

    uint8_t macIn[32 + 8 + sizeof(TrialPayload)]{};
    memcpy(macIn, key, 32);
    memcpy(macIn + 32, outBlob.nonce, 8);
    memcpy(macIn + 40, outBlob.cipher, sizeof(TrialPayload));
    BYTE macFull[32]{};
    ComputeSha256(hSha, macIn, sizeof(macIn), macFull);
    memcpy(outBlob.mac, macFull, 16);

    SecureZeroMemory(macIn, sizeof(macIn));
    SecureZeroMemory(macFull, sizeof(macFull));
    SecureZeroMemory(key, sizeof(key));
    BCryptCloseAlgorithmProvider(hSha, 0);
    return true;
}

bool OpenTrialBlob(const std::string& hwid, const uint8_t* bytes, size_t len, TrialPayload& outPl) {
    if (len != sizeof(TrialDiskBlob)) return false;
    TrialDiskBlob blob{};
    memcpy(&blob, bytes, sizeof(blob));
    if (blob.hdrMagic != TRIAL_BLOB_HDR_MAGIC) return false;

    BYTE key[32]{};
    if (!DeriveTrialKey(hwid, key)) return false;
    BCRYPT_ALG_HANDLE hSha = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        SecureZeroMemory(key, sizeof(key));
        return false;
    }

    uint8_t macIn[32 + 8 + sizeof(TrialPayload)]{};
    memcpy(macIn, key, 32);
    memcpy(macIn + 32, blob.nonce, 8);
    memcpy(macIn + 40, blob.cipher, sizeof(TrialPayload));
    BYTE macFull[32]{};
    ComputeSha256(hSha, macIn, sizeof(macIn), macFull);
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= (macFull[i] ^ blob.mac[i]);
    SecureZeroMemory(macIn, sizeof(macIn));
    SecureZeroMemory(macFull, sizeof(macFull));
    if (diff != 0) {
        SecureZeroMemory(key, sizeof(key));
        BCryptCloseAlgorithmProvider(hSha, 0);
        return false;
    }

    BYTE streamInput[40]{};
    memcpy(streamInput, key, 32);
    memcpy(streamInput + 32, blob.nonce, 8);
    BYTE streamA[32]{}, streamB[32]{};
    ComputeSha256(hSha, streamInput, sizeof(streamInput), streamA);
    streamInput[32] ^= 0xA5;
    ComputeSha256(hSha, streamInput, sizeof(streamInput), streamB);
    SecureZeroMemory(streamInput, sizeof(streamInput));

    uint8_t* raw = reinterpret_cast<uint8_t*>(&outPl);
    for (size_t i = 0; i < sizeof(TrialPayload); ++i) {
        uint8_t kbyte = (i < 32) ? streamA[i] : streamB[i - 32];
        raw[i] = blob.cipher[i] ^ kbyte;
    }
    SecureZeroMemory(streamA, sizeof(streamA));
    SecureZeroMemory(streamB, sizeof(streamB));
    SecureZeroMemory(key, sizeof(key));
    BCryptCloseAlgorithmProvider(hSha, 0);
    return (outPl.magic == TRIAL_PAYLOAD_MAGIC && outPl.version == 1);
}

void AbsorbTrialAnchor(const std::string& physTrialId, const std::string& legacyV1,
                       bool exists, const std::vector<uint8_t>& buf,
                       TrialPayload& merged, int& validCount, bool& anyCorrupt) {
    if (!exists) return;
    TrialPayload p{};
    if (!OpenTrialBlob(physTrialId, buf.data(), buf.size(), p)) {
        if (legacyV1.empty() || !OpenTrialBlob(legacyV1, buf.data(), buf.size(), p)) {
            anyCorrupt = true;
            return;
        }
    }
    ++validCount;
    merged.usedSeconds = std::max(merged.usedSeconds, p.usedSeconds);
    if (p.firstWallSec > 0 && p.firstWallSec < merged.firstWallSec) merged.firstWallSec = p.firstWallSec;
    if (p.maxWallSec > merged.maxWallSec) merged.maxWallSec = p.maxWallSec;
    merged.flags |= p.flags;
}

bool ReadTrialRegAnchor(HKEY root, REGSAM access, std::vector<uint8_t>& outBytes) {
    HKEY hk = NULL;
    bool exists = false;
    if (RegOpenKeyExW(root, L"Software\\Classes\\CLSID\\{7C3E2A90-4F18-4D62-B853-9A0E61C4D217}",
                      0, access, &hk) == ERROR_SUCCESS) {
        DWORD sz = 0, ty = 0;
        if (RegQueryValueExW(hk, L"ConfigData", NULL, &ty, NULL, &sz) == ERROR_SUCCESS && sz > 0 && sz < 512) {
            exists = true;
            outBytes.resize(sz);
            RegQueryValueExW(hk, L"ConfigData", NULL, &ty, outBytes.data(), &sz);
        }
        RegCloseKey(hk);
    }
    return exists;
}

} // namespace

uint64_t GetUnixUtcSeconds() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ui{};
    ui.LowPart  = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    constexpr uint64_t EPOCH_DIFF = 11644473600ULL;
    uint64_t sec = ui.QuadPart / 10000000ULL;
    return (sec > EPOCH_DIFF) ? (sec - EPOCH_DIFF) : 0;
}

uint64_t QueryNetUtcSeconds() {
    HINTERNET hSess = WinHttpOpen(L"CR1M-Pro-Mod/2.3", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return 0;
    WinHttpSetTimeouts(hSess, 500, 500, 500, 500);
    HINTERNET hConn = WinHttpConnect(hSess, L"www.microsoft.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    uint64_t res = 0;
    if (hConn) {
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"HEAD", L"/", NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (hReq) {
            if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hReq, NULL)) {
                SYSTEMTIME st{};
                DWORD stLen = sizeof(st);
                if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_DATE | WINHTTP_QUERY_FLAG_SYSTEMTIME, NULL, &st, &stLen, NULL)) {
                    FILETIME ft{};
                    if (SystemTimeToFileTime(&st, &ft)) {
                        ULARGE_INTEGER ui{};
                        ui.LowPart  = ft.dwLowDateTime;
                        ui.HighPart = ft.dwHighDateTime;
                        constexpr uint64_t EPOCH_DIFF = 11644473600ULL;
                        uint64_t sec = ui.QuadPart / 10000000ULL;
                        if (sec > EPOCH_DIFF) res = sec - EPOCH_DIFF;
                    }
                }
            }
            WinHttpCloseHandle(hReq);
        }
        WinHttpCloseHandle(hConn);
    }
    WinHttpCloseHandle(hSess);
    return res;
}

uint64_t ReadNetWallLatest() {
    LONG64 v = InterlockedCompareExchange64(&gNetWallLatest, 0, 0);
    return (v > 0) ? static_cast<uint64_t>(v) : 0ULL;
}

void UpdateNetWallLatest(uint64_t utcSec) {
    if (utcSec > 0) {
        InterlockedExchange64(&gNetWallLatest, static_cast<LONG64>(utcSec));
    }
}

void StartAsyncNetUtcCheck(HANDLE& hThread) {
    if (hThread != NULL) {
        if (WaitForSingleObject(hThread, 0) != WAIT_OBJECT_0) return;
        CloseHandle(hThread);
        hThread = NULL;
    }
    if (InterlockedCompareExchange(&gNetThreadRunning, 1, 0) != 0) return;
    HANDLE hNew = CreateThread(NULL, 0, NetUtcCheckThreadProc, NULL, 0, NULL);
    if (!hNew) {
        InterlockedExchange(&gNetThreadRunning, 0);
        return;
    }
    hThread = hNew;
}

void FinishAsyncNetUtcCheck(HANDLE& hThread, DWORD waitMs) {
    if (hThread != NULL) {
        WaitForSingleObject(hThread, waitMs);
        CloseHandle(hThread);
        hThread = NULL;
    }
}

void SaveTrialAnchors(const std::string& trialKeyId, const TrialPayload& pl) {
    TrialDiskBlob blob{};
    if (!SealTrialBlob(trialKeyId, pl, blob)) return;

    const wchar_t* regKey = L"Software\\Classes\\CLSID\\{7C3E2A90-4F18-4D62-B853-9A0E61C4D217}";
    const wchar_t* regVal = L"ConfigData";

    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hk, regVal, 0, REG_BINARY, reinterpret_cast<const BYTE*>(&blob), sizeof(blob));
        RegCloseKey(hk);
    }

    std::string dir1 = GetAppDataBaseDir();
    WriteFileBytesHidden(dir1, dir1 + "\\.td_pub_cache.bin", &blob, sizeof(blob));

    std::string dir2 = GetLocalAppDataDirA() + "\\CR1M_PublicCache";
    WriteFileBytesHidden(dir2, dir2 + "\\td_metrics.bin", &blob, sizeof(blob));

    std::string dir3 = GetProgramDataBaseDir();
    if (!dir3.empty()) {
        WriteFileBytesHidden(dir3, dir3 + "\\.pub_td_metrics.dat", &blob, sizeof(blob));
    }

    std::string dir4 = GetPublicDocsDirA();
    if (!dir4.empty()) {
        WriteFileBytesHidden(dir4, dir4 + "\\.cr1m_td_pub.bin", &blob, sizeof(blob));
    }

    HKEY hklm = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regKey, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hklm, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hklm, regVal, 0, REG_BINARY, reinterpret_cast<const BYTE*>(&blob), sizeof(blob));
        RegCloseKey(hklm);
    }
}

TrialPayload LoadAndReconcileTrial(const HwidBundle& hb, bool& outClockTampered, bool& outSpoofBlocked) {
    outClockTampered = false;
    outSpoofBlocked = hb.spoof.hasTrialBlockFlag();

    uint64_t sysWall = GetUnixUtcSeconds();
    uint64_t netWall = QueryNetUtcSeconds();
    UpdateNetWallLatest(netWall);
    if (netWall > 0 && sysWall + 120 < netWall) {
        outClockTampered = true;
    }
    uint64_t effectiveWall = std::max(sysWall, netWall);

    bool regExists = false, hklmExists = false, f1Exists = false, f2Exists = false, f3Exists = false, f4Exists = false;
    std::vector<uint8_t> regBytes, hklmBytes, f1Bytes, f2Bytes, f3Bytes, f4Bytes;

    regExists  = ReadTrialRegAnchor(HKEY_CURRENT_USER, KEY_READ, regBytes);
    hklmExists = ReadTrialRegAnchor(HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY, hklmBytes);
    ReadFileBytes(GetAppDataBaseDir() + "\\.td_pub_cache.bin", f1Bytes, f1Exists);
    ReadFileBytes(GetLocalAppDataDirA() + "\\CR1M_PublicCache\\td_metrics.bin", f2Bytes, f2Exists);

    std::string pdDir = GetProgramDataBaseDir();
    if (!pdDir.empty()) ReadFileBytes(pdDir + "\\.pub_td_metrics.dat", f3Bytes, f3Exists);
    std::string pubDir = GetPublicDocsDirA();
    if (!pubDir.empty()) ReadFileBytes(pubDir + "\\.cr1m_td_pub.bin", f4Bytes, f4Exists);

    bool anyPresent = regExists || hklmExists || f1Exists || f2Exists || f3Exists || f4Exists;
    int validCount = 0;
    bool anyCorrupt = false;
    TrialPayload merged{};
    merged.magic        = TRIAL_PAYLOAD_MAGIC;
    merged.version      = 1;
    merged.usedSeconds  = 0;
    merged.firstWallSec = effectiveWall;
    merged.maxWallSec   = effectiveWall;
    merged.lastUpSec    = GetTickCount64() / 1000ULL;
    merged.flags        = 0;
    merged.reserved     = 0;

    AbsorbTrialAnchor(hb.physTrialId, hb.v1, regExists,  regBytes,  merged, validCount, anyCorrupt);
    AbsorbTrialAnchor(hb.physTrialId, hb.v1, hklmExists, hklmBytes, merged, validCount, anyCorrupt);
    AbsorbTrialAnchor(hb.physTrialId, hb.v1, f1Exists,   f1Bytes,   merged, validCount, anyCorrupt);
    AbsorbTrialAnchor(hb.physTrialId, hb.v1, f2Exists,   f2Bytes,   merged, validCount, anyCorrupt);
    AbsorbTrialAnchor(hb.physTrialId, hb.v1, f3Exists,   f3Bytes,   merged, validCount, anyCorrupt);
    AbsorbTrialAnchor(hb.physTrialId, hb.v1, f4Exists,   f4Bytes,   merged, validCount, anyCorrupt);

    if (anyCorrupt && validCount == 0 && anyPresent) outClockTampered = true;
    if (validCount > 0 && merged.maxWallSec > 0 && sysWall + 15 < merged.maxWallSec) outClockTampered = true;
    if (outClockTampered) {
        merged.usedSeconds = TRIAL_BUDGET_SECONDS;
        merged.flags |= 1u;
    }
    if (merged.usedSeconds >= TRIAL_BUDGET_SECONDS) {
        merged.usedSeconds = TRIAL_BUDGET_SECONDS;
        merged.flags |= 1u;
    }
    SaveTrialAnchors(hb.physTrialId, merged);
    return merged;
}

std::optional<AuthProof> ActivateTrialTokenFromPub() {
    uint64_t pubHash = detail::ComputeFnv1a64(std::span<const uint8_t>(detail::kRsaPubBlob));
    if (pubHash != (detail::kExpPubX ^ detail::kPubMask)) {
        return std::nullopt;
    }
    return AuthProof(pubHash ^ detail::kTrialSalt, true, 12ULL);
}

} // namespace cr1m
