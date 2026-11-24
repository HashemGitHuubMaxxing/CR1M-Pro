// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/auth.hpp"
#include "cr1m/config.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/trial.hpp"
#include "cr1m/util.hpp"
#include <winhttp.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace cr1m {

namespace {

std::string GetRevocationCertPath(const std::string& licDir) {
    return licDir + "\\revoked.cert";
}

void SaveRevocationTombstone(const std::string& licDir, const std::string& certStr) {
    if (certStr.empty()) return;
    if (!licDir.empty()) {
        SaveLicenseKeyAtomic(licDir, GetRevocationCertPath(licDir), certStr);
    }
    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\CR1MPro", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        std::wstring wVal = Utf8ToWide(certStr);
        RegSetValueExW(hk, L"RevocationCert", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(wVal.c_str()),
                       static_cast<DWORD>((wVal.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
    }
}

void ClearRevocationTombstone(const std::string& licDir) {
    if (!licDir.empty()) {
        DeleteFileW(Utf8ToWide(GetRevocationCertPath(licDir)).c_str());
    }
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\CR1MPro", 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueW(hk, L"RevocationCert");
        RegCloseKey(hk);
    }
}

bool ParseAndVerifySignedStatusCert(const std::string& certText,
                                    const std::string& expectedKey,
                                    const std::string& expectedHwidHash,
                                    const std::string& expectedNonce,
                                    std::string& outVerdict,
                                    std::string& outCheckedAt) {
    outVerdict.clear();
    outCheckedAt.clear();
    std::string clean = StripWhitespace(certText);
    if (clean.size() < 620 || clean.size() > 2400) return false;

    std::string parts[7];
    size_t start = 0;
    for (int p = 0; p < 7; ++p) {
        size_t sep = clean.find('|', start);
        if (p < 6) {
            if (sep == std::string::npos) return false;
            parts[p] = clean.substr(start, sep - start);
            start = sep + 1;
        } else {
            if (sep != std::string::npos) return false;
            parts[p] = clean.substr(start);
        }
    }

    if (!CtEqualStr(parts[0], "CR1M-STATUS-V1")) return false;
    if (!CtEqualStr(parts[1], expectedKey)) return false;
    if (!CtEqualStr(parts[2], expectedHwidHash)) return false;

    const std::string& verdict   = parts[3];
    const std::string& nonce     = parts[4];
    const std::string& checkedAt = parts[5];
    const std::string& sigHex    = parts[6];

    if (verdict != "active" && verdict != "revoked" && verdict != "hwid_mismatch") return false;
    if (nonce.size() < 16 || nonce.size() > 64) return false;
    if (!expectedNonce.empty() && !CtEqualStr(nonce, expectedNonce)) return false;
    if (checkedAt.size() < 10 || checkedAt.size() > 64) return false;
    if (sigHex.size() != 512) return false;

    std::string canonical = parts[0] + "|" + parts[1] + "|" + parts[2] + "|" +
                            verdict + "|" + nonce + "|" + checkedAt;
    bool sigOk = VerifyRsaSha256WithEmbeddedPub(canonical, sigHex, nullptr);
    WipeStr(canonical);
    if (!sigOk) return false;

    outVerdict = verdict;
    outCheckedAt = checkedAt;
    return true;
}

bool LoadValidLocalTombstone(const std::string& licDir,
                             const std::string& licenseKey,
                             const std::string& localHwidHash,
                             const std::string& receiptIssuedAt,
                             std::string& outVerdict,
                             std::string& outCheckedAt) {
    outVerdict.clear();
    outCheckedAt.clear();

    std::vector<std::string> candidates;
    if (!licDir.empty()) {
        std::string fileCert;
        if (ReadFileUtf8W(Utf8ToWide(GetRevocationCertPath(licDir)), fileCert) && !fileCert.empty()) {
            candidates.push_back(fileCert);
        }
    }

    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\CR1MPro", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD ty = 0, cb = 0;
        if (RegQueryValueExW(hk, L"RevocationCert", NULL, &ty, NULL, &cb) == ERROR_SUCCESS &&
            ty == REG_SZ && cb > sizeof(wchar_t) && cb <= 8192) {
            std::wstring wBuf(cb / sizeof(wchar_t), L'\0');
            if (RegQueryValueExW(hk, L"RevocationCert", NULL, &ty, reinterpret_cast<LPBYTE>(wBuf.data()), &cb) == ERROR_SUCCESS) {
                while (!wBuf.empty() && wBuf.back() == L'\0') wBuf.pop_back();
                if (!wBuf.empty()) candidates.push_back(WideToUtf8(wBuf));
            }
        }
        RegCloseKey(hk);
    }

    bool found = false;
    for (const auto& c : candidates) {
        std::string v, ts;
        if (ParseAndVerifySignedStatusCert(c, licenseKey, localHwidHash, "", v, ts)) {
            if ((v == "revoked" || v == "hwid_mismatch") && ts >= receiptIssuedAt) {
                if (!found || ts > outCheckedAt) {
                    outVerdict = v;
                    outCheckedAt = ts;
                    found = true;
                }
            }
        }
    }
    return found;
}

void PrintRevocationBlockMessage(const std::string& verdict) {
    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    if (verdict == "hwid_mismatch") {
        ConPrint(TR("\n  [X] This license key has been transferred to another PC.\n"
                    "      If you believe this is a mistake, contact support@cr1m.net.\n\n",
                    "\n  [X] \xD0\xAD\xD1\x82\xD0\xBE\xD1\x82 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xB1\xD1\x8B\xD0\xBB \xD0\xBF\xD0\xB5\xD1\x80\xD0\xB5\xD0\xBD\xD0\xB5\xD1\x81\xD1\x91\xD0\xBD \xD0\xBD\xD0\xB0 \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xBE\xD0\xB9 \xD0\x9F\xD0\x9A.\n"
                    "      \xD0\x95\xD1\x81\xD0\xBB\xD0\xB8 \xD1\x8D\xD1\x82\xD0\xBE \xD0\xBE\xD1\x88\xD0\xB8\xD0\xB1\xD0\xBA\xD0\xB0, \xD0\xBD\xD0\xB0\xD0\xBF\xD0\xB8\xD1\x88\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xBD\xD0\xB0 support@cr1m.net.\n\n"));
    } else {
        ConPrint(TR("\n  [X] This license key has been revoked or invalidated.\n"
                    "      If you believe this is a mistake, contact support@cr1m.net.\n\n",
                    "\n  [X] \xD0\xAD\xD1\x82\xD0\xBE\xD1\x82 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xB1\xD1\x8B\xD0\xBB \xD0\xBE\xD1\x82\xD0\xBE\xD0\xB7\xD0\xB2\xD0\xB0\xD0\xBD \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB0\xD0\xBD\xD0\xBD\xD1\x83\xD0\xBB\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD.\n"
                    "      \xD0\x95\xD1\x81\xD0\xBB\xD0\xB8 \xD1\x8D\xD1\x82\xD0\xBE \xD0\xBE\xD1\x88\xD0\xB8\xD0\xB1\xD0\xBA\xD0\xB0, \xD0\xBD\xD0\xB0\xD0\xBF\xD0\xB8\xD1\x88\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xBD\xD0\xB0 support@cr1m.net.\n\n"));
    }
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::optional<AuthProof> TryLoadOrActivateKeyFile(const HwidBundle& hb,
                                                  const std::string& filePath,
                                                  const std::string& licDir,
                                                  const std::string& cachedLicPath,
                                                  bool nonInteractive,
                                                  std::string& outLicenseKey,
                                                  bool& outRevoked) {
    outRevoked = false;
    outLicenseKey.clear();
    std::string text;
    if (!ReadFileUtf8W(Utf8ToWide(filePath), text)) return std::nullopt;
    std::string raw = Trim(text);
    if (raw.empty()) return std::nullopt;

    if (raw.rfind("CR1M-V2|", 0) == 0) {
        std::string receiptIssuedAt;
        auto proof = VerifySignedReceipt(hb, raw, outLicenseKey, &receiptIssuedAt);
        if (!proof) return std::nullopt;
        if (!CheckLicenseRevocationFailOpen(hb, outLicenseKey, receiptIssuedAt, licDir, cachedLicPath, filePath)) {
            outRevoked = true;
            outLicenseKey.clear();
            proof->revoke();
            return std::nullopt;
        }
        if (filePath != cachedLicPath) {
            SaveLicenseKeyAtomic(licDir, cachedLicPath, StripWhitespace(raw));
        }
        return proof;
    }

    std::string normKey = NormalizeLicenseKeyPaste(raw);
    if (IsValidLicenseKeyFormat(normKey)) {
        if (!ConfirmSpooferBeforeBind(hb, nonInteractive)) return std::nullopt;
        ConPrint(TR("  [+] Found license.key — activating online...\n",
                    "  [+] \xD0\x9D\xD0\xB0\xD0\xB9\xD0\xB4\xD0\xB5\xD0\xBD license.key \xE2\x80\x94 \xD0\xB2\xD1\x8B\xD0\xBF\xD0\xBE\xD0\xBB\xD0\xBD\xD1\x8F\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F \xD0\xBE\xD0\xBD\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD-\xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F...\n"));
        std::optional<AuthProof> proof;
        ActivateStatus st = ActivateLicenseKeyOnline(hb, normKey, licDir, cachedLicPath, outLicenseKey, proof);
        if (st == ActivateStatus::Ok && proof) {
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("  [OK] License activated and bound to this PC!\n\n",
                        "  [OK] \xD0\x9B\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD1\x8F \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xB8 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB7\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xBA \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC\xD1\x83 \xD0\x9F\xD0\x9A!\n\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            return proof;
        }
        PrintActivationError(st);
        if (st == ActivateStatus::Revoked) outRevoked = true;
    }
    return std::nullopt;
}

} // namespace

bool ComputeSha256(BCRYPT_ALG_HANDLE hShaAlg, const void* data, size_t len, BYTE* outHash) {
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hShaAlg, &hHash, NULL, 0, NULL, 0, 0))) return false;
    bool ok = BCRYPT_SUCCESS(BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
                                            static_cast<ULONG>(len), 0)) &&
              BCRYPT_SUCCESS(BCryptFinishHash(hHash, outHash, 32, 0));
    BCryptDestroyHash(hHash);
    return ok;
}

bool ComputeSha256Bytes(const void* data, size_t len, BYTE outHash[32]) {
    BCRYPT_ALG_HANDLE hShaAlg = NULL;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hShaAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        ok = ComputeSha256(hShaAlg, data, len, outHash);
        BCryptCloseAlgorithmProvider(hShaAlg, 0);
    }
    return ok;
}

bool ComputeLocalSiliconHwidHash(const HwidBundle& hb, std::string& outLowerHex) {
    outLowerHex.clear();
    if (hb.physTrialId.size() < 8) return false;
    BYTE digest[32]{};
    if (!ComputeSha256Bytes(hb.physTrialId.data(), hb.physTrialId.size(), digest)) return false;
    outLowerHex = BytesToLowerHex(digest, sizeof(digest));
    SecureZeroMemory(digest, sizeof(digest));
    return outLowerHex.size() == 64;
}

bool HttpsPostJson(const std::wstring& host, const std::wstring& path,
                   const std::string& jsonBody, DWORD connectMs, DWORD rwMs,
                   DWORD& outHttpCode, std::string& outRespBody) {
    outHttpCode = 0;
    outRespBody.clear();

    HINTERNET hSess = WinHttpOpen(L"CR1M-Pro-Mod/2.3", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) {
        hSess = WinHttpOpen(L"CR1M-Pro-Mod/2.3", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSess) {
        hSess = WinHttpOpen(L"CR1M-Pro-Mod/2.3", WINHTTP_ACCESS_TYPE_NO_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSess) return false;

    WinHttpSetTimeouts(hSess, static_cast<int>(connectMs), static_cast<int>(connectMs),
                       static_cast<int>(rwMs), static_cast<int>(rwMs));

    bool ok = false;
    HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConn) {
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (hReq) {
            std::wstring hdrs = L"Content-Type: application/json\r\nAccept: application/json\r\n";
            BOOL sent = WinHttpSendRequest(hReq, hdrs.c_str(), static_cast<DWORD>(hdrs.size()),
                                           const_cast<char*>(jsonBody.data()), static_cast<DWORD>(jsonBody.size()),
                                           static_cast<DWORD>(jsonBody.size()), 0);
            if (sent && WinHttpReceiveResponse(hReq, NULL)) {
                DWORD code = 0, codeLen = sizeof(code);
                if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                        NULL, &code, &codeLen, NULL)) {
                    outHttpCode = code;
                    bool readOk = true;
                    while (outRespBody.size() < 65536) {
                        DWORD avail = 0;
                        if (!WinHttpQueryDataAvailable(hReq, &avail)) { readOk = false; break; }
                        if (avail == 0) break;
                        size_t room = 65536 - outRespBody.size();
                        DWORD want = (avail > room) ? static_cast<DWORD>(room) : avail;
                        size_t prev = outRespBody.size();
                        outRespBody.resize(prev + want);
                        DWORD got = 0;
                        if (!WinHttpReadData(hReq, &outRespBody[prev], want, &got)) {
                            outRespBody.resize(prev);
                            readOk = false;
                            break;
                        }
                        outRespBody.resize(prev + got);
                        if (got == 0) break;
                    }
                    ok = readOk;
                    if (!readOk) {
                        outRespBody.clear();
                        outHttpCode = 0;
                    }
                }
            }
            WinHttpCloseHandle(hReq);
        }
        WinHttpCloseHandle(hConn);
    }
    WinHttpCloseHandle(hSess);
    return ok;
}

bool VerifyRsaSha256WithEmbeddedPub(const std::string& payload,
                                    const std::string& sigHex,
                                    uint64_t* outPubHash) {
    if (outPubHash) *outPubHash = 0;
    if (sigHex.size() != 512) return false;

    std::vector<BYTE> sigBytes;
    if (!HexDecode(sigHex, sigBytes) || sigBytes.size() != 256) return false;

    BCRYPT_ALG_HANDLE hRsaAlg = NULL, hShaAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0))) {
        SecureZeroMemory(sigBytes.data(), sigBytes.size());
        return false;
    }
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hShaAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        SecureZeroMemory(sigBytes.data(), sigBytes.size());
        return false;
    }

    BYTE pubBlob[detail::kRsaPubBlob.size()]{};
    memcpy(pubBlob, detail::kRsaPubBlob.data(), sizeof(pubBlob));
    uint64_t pubHash = detail::ComputeFnv1a64(std::span<const uint8_t>(pubBlob, sizeof(pubBlob)));
    if (pubHash != (detail::kExpPubX ^ detail::kPubMask)) {
        SecureZeroMemory(pubBlob, sizeof(pubBlob));
        BCryptCloseAlgorithmProvider(hShaAlg, 0);
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        SecureZeroMemory(sigBytes.data(), sigBytes.size());
        return false;
    }

    BCRYPT_KEY_HANDLE hPubKey = NULL;
    NTSTATUS st = BCryptImportKeyPair(hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hPubKey, pubBlob, sizeof(pubBlob), 0);
    SecureZeroMemory(pubBlob, sizeof(pubBlob));
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hShaAlg, 0);
        BCryptCloseAlgorithmProvider(hRsaAlg, 0);
        SecureZeroMemory(sigBytes.data(), sigBytes.size());
        return false;
    }

    BYTE hash[32]{};
    bool ok = false;
    if (ComputeSha256(hShaAlg, payload.data(), payload.size(), hash)) {
        BCRYPT_PKCS1_PADDING_INFO pad{ BCRYPT_SHA256_ALGORITHM };
        st = BCryptVerifySignature(hPubKey, &pad, hash, sizeof(hash),
                                   sigBytes.data(), static_cast<ULONG>(sigBytes.size()), BCRYPT_PAD_PKCS1);
        ok = BCRYPT_SUCCESS(st);
        if (ok && outPubHash) {
            *outPubHash = pubHash;
        }
    }
    SecureZeroMemory(hash, sizeof(hash));
    SecureZeroMemory(sigBytes.data(), sigBytes.size());

    BCryptDestroyKey(hPubKey);
    BCryptCloseAlgorithmProvider(hShaAlg, 0);
    BCryptCloseAlgorithmProvider(hRsaAlg, 0);
    return ok;
}

std::optional<AuthProof> VerifySignedReceipt(const HwidBundle& hb,
                                             const std::string& receiptText,
                                             std::string& outLicenseKey,
                                             std::string* outIssuedAt) {
    outLicenseKey.clear();
    if (outIssuedAt) outIssuedAt->clear();

    std::string clean = StripWhitespace(receiptText);
    if (clean.size() < 600 || clean.size() > 2048) return std::nullopt;

    std::string parts[5];
    size_t start = 0;
    for (int p = 0; p < 5; ++p) {
        size_t sep = clean.find('|', start);
        if (p < 4) {
            if (sep == std::string::npos) return std::nullopt;
            parts[p] = clean.substr(start, sep - start);
            start = sep + 1;
        } else {
            if (sep != std::string::npos) return std::nullopt;
            parts[p] = clean.substr(start);
        }
    }

    if (!CtEqualStr(parts[0], "CR1M-V2")) return std::nullopt;

    const std::string& licenseKey      = parts[1];
    const std::string& receiptHwidHash = parts[2];
    const std::string& issuedAt        = parts[3];
    const std::string& sigHex          = parts[4];

    if (!IsValidLicenseKeyFormat(licenseKey)) return std::nullopt;
    if (receiptHwidHash.size() != 64) return std::nullopt;
    if (issuedAt.size() < 10 || issuedAt.size() > 64) return std::nullopt;
    if (sigHex.size() != 512) return std::nullopt;

    std::string localHwidHash;
    if (!ComputeLocalSiliconHwidHash(hb, localHwidHash)) return std::nullopt;
    bool hwidMatch = CtEqualStr(localHwidHash, receiptHwidHash);
    WipeStr(localHwidHash);
    if (!hwidMatch) return std::nullopt;

    std::string payload = licenseKey + "|" + receiptHwidHash + "|" + issuedAt;
    uint64_t pubHash = 0;
    bool ok = VerifyRsaSha256WithEmbeddedPub(payload, sigHex, &pubHash);
    WipeStr(payload);
    if (!ok) return std::nullopt;

    outLicenseKey = licenseKey;
    if (outIssuedAt) *outIssuedAt = issuedAt;
    return AuthProof(pubHash ^ detail::kTokSalt, false, 0);
}

bool CheckLicenseRevocationFailOpen(const HwidBundle& hb,
                                    const std::string& licenseKey,
                                    const std::string& receiptIssuedAt,
                                    const std::string& licDir,
                                    const std::string& cachedLicPath,
                                    const std::string& sourceFilePath) {
    if (!IsValidLicenseKeyFormat(licenseKey)) return true;

    std::string localHwidHash;
    if (!ComputeLocalSiliconHwidHash(hb, localHwidHash)) return true;

    std::string tombVerdict, tombCheckedAt;
    bool hasTombstone = LoadValidLocalTombstone(licDir, licenseKey, localHwidHash, receiptIssuedAt,
                                                tombVerdict, tombCheckedAt);

    BYTE nonceBytes[16]{};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonceBytes, sizeof(nonceBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        WipeStr(localHwidHash);
        if (hasTombstone) {
            if (!cachedLicPath.empty()) DeleteFileW(Utf8ToWide(cachedLicPath).c_str());
            if (!sourceFilePath.empty() && sourceFilePath != cachedLicPath) DeleteFileW(Utf8ToWide(sourceFilePath).c_str());
            PrintRevocationBlockMessage(tombVerdict);
            return false;
        }
        return true;
    }
    std::string nonce = BytesToLowerHex(nonceBytes, sizeof(nonceBytes));
    SecureZeroMemory(nonceBytes, sizeof(nonceBytes));

    std::string body = "{\"licenseKey\":\"" + JsonEscape(licenseKey) +
                       "\",\"hwidHash\":\"" + JsonEscape(localHwidHash) +
                       "\",\"nonce\":\"" + JsonEscape(nonce) + "\"}";

    DWORD httpCode = 0;
    std::string resp;
    bool gotHttp = HttpsPostJson(CR1M_API_HOST_W, L"/api/license/status", body, 1500, 2000, httpCode, resp);
    WipeStr(body);

    if (gotHttp && httpCode == 200) {
        bool apiOk = false;
        std::string proto, respKey, respHwidHash, verdict, respNonce, checkedAt, sigAlg, signature;
        if (JsonExtractBoolField(resp, "ok", apiOk) && apiOk &&
            JsonExtractStringField(resp, "protocol", proto) &&
            JsonExtractStringField(resp, "licenseKey", respKey) &&
            JsonExtractStringField(resp, "hwidHash", respHwidHash) &&
            JsonExtractStringField(resp, "verdict", verdict) &&
            JsonExtractStringField(resp, "nonce", respNonce) &&
            JsonExtractStringField(resp, "checkedAt", checkedAt) &&
            JsonExtractStringField(resp, "signatureAlg", sigAlg) &&
            JsonExtractStringField(resp, "signature", signature) &&
            sigAlg == "rsa-sha256") {

            std::string certStr = proto + "|" + respKey + "|" + respHwidHash + "|" +
                                  verdict + "|" + respNonce + "|" + checkedAt + "|" + signature;
            std::string verifiedVerdict, verifiedCheckedAt;
            if (ParseAndVerifySignedStatusCert(certStr, licenseKey, localHwidHash, nonce,
                                               verifiedVerdict, verifiedCheckedAt)) {
                if (verifiedVerdict == "revoked" || verifiedVerdict == "hwid_mismatch") {
                    if (verifiedCheckedAt >= receiptIssuedAt) {
                        SaveRevocationTombstone(licDir, certStr);
                        if (!cachedLicPath.empty()) DeleteFileW(Utf8ToWide(cachedLicPath).c_str());
                        if (!sourceFilePath.empty() && sourceFilePath != cachedLicPath) {
                            DeleteFileW(Utf8ToWide(sourceFilePath).c_str());
                        }
                        WipeStr(certStr);
                        WipeStr(localHwidHash);
                        WipeStr(nonce);
                        PrintRevocationBlockMessage(verifiedVerdict);
                        return false;
                    }
                } else if (verifiedVerdict == "active") {
                    if (hasTombstone && verifiedCheckedAt > tombCheckedAt) {
                        ClearRevocationTombstone(licDir);
                    }
                    WipeStr(certStr);
                    WipeStr(localHwidHash);
                    WipeStr(nonce);
                    return true;
                }
            }
            WipeStr(certStr);
        }
    }

    WipeStr(localHwidHash);
    WipeStr(nonce);

    if (hasTombstone) {
        if (!cachedLicPath.empty()) DeleteFileW(Utf8ToWide(cachedLicPath).c_str());
        if (!sourceFilePath.empty() && sourceFilePath != cachedLicPath) {
            DeleteFileW(Utf8ToWide(sourceFilePath).c_str());
        }
        PrintRevocationBlockMessage(tombVerdict);
        return false;
    }

    return true;
}

ActivateStatus ActivateLicenseKeyOnline(const HwidBundle& hb,
                                        const std::string& rawInput,
                                        const std::string& licDir,
                                        const std::string& licPath,
                                        std::string& outLicenseKey,
                                        std::optional<AuthProof>& outProof) {
    outLicenseKey.clear();
    outProof.reset();

    std::string key = NormalizeLicenseKeyPaste(rawInput);
    if (!IsValidLicenseKeyFormat(key)) {
        return ActivateStatus::InvalidFormat;
    }

    std::string reqJson = "{\"licenseKey\":\"" + JsonEscape(key) +
                          "\",\"hwid\":\"" + JsonEscape(hb.physTrialId) + "\"}";

    DWORD httpCode = 0;
    std::string resp;
    bool gotHttp = HttpsPostJson(CR1M_API_HOST_W, L"/api/license/activate", reqJson, 8000, 10000, httpCode, resp);
    if (!gotHttp) {
        Sleep(350);
        gotHttp = HttpsPostJson(CR1M_API_HOST_W, L"/api/license/activate", reqJson, 8000, 10000, httpCode, resp);
    }
    WipeStr(reqJson);

    if (!gotHttp) return ActivateStatus::NetworkError;

    std::string errCode;
    JsonExtractStringField(resp, "error", errCode);

    if (httpCode == 400) {
        if (errCode == "INVALID_KEY_FORMAT") return ActivateStatus::InvalidFormat;
        return ActivateStatus::ServerError;
    }
    if (httpCode == 404) {
        if (errCode == "LICENSE_NOT_FOUND") return ActivateStatus::NotFound;
        return ActivateStatus::ServerError;
    }
    if (httpCode == 429) return ActivateStatus::RateLimited;
    if (httpCode == 403) {
        if (errCode == "LICENSE_REVOKED") return ActivateStatus::Revoked;
        if (errCode == "HWID_MISMATCH") return ActivateStatus::HwidMismatch;
        return ActivateStatus::ServerError;
    }
    if (httpCode != 200) return ActivateStatus::ServerError;

    bool apiOk = false;
    std::string respKey, hwidHash, issuedAt, signature, sigAlg;
    if (!JsonExtractBoolField(resp, "ok", apiOk) || !apiOk ||
        !JsonExtractStringField(resp, "licenseKey", respKey) ||
        !JsonExtractStringField(resp, "hwidHash", hwidHash) ||
        !JsonExtractStringField(resp, "issuedAt", issuedAt) ||
        !JsonExtractStringField(resp, "signature", signature) ||
        !JsonExtractStringField(resp, "signatureAlg", sigAlg)) {
        return ActivateStatus::ServerError;
    }

    if (respKey != key || sigAlg != "rsa-sha256") {
        return ActivateStatus::BadSignature;
    }

    std::string receipt = "CR1M-V2|" + respKey + "|" + hwidHash + "|" + issuedAt + "|" + signature;
    std::string verifiedKey;
    auto proof = VerifySignedReceipt(hb, receipt, verifiedKey);
    if (!proof) {
        WipeStr(receipt);
        return ActivateStatus::BadSignature;
    }

    SaveLicenseKeyAtomic(licDir, licPath, receipt);
    ClearRevocationTombstone(licDir);
    WipeStr(receipt);
    outLicenseKey = verifiedKey;
    outProof = std::move(proof);
    return ActivateStatus::Ok;
}

void PrintActivationError(ActivateStatus st) {
    SetColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    if (st == ActivateStatus::InvalidFormat) {
        ConPrint(TR("  [X] Invalid license key format. Expected: CR1M-XXXX-XXXX-XXXX\n",
                    "  [X] \xD0\x9D\xD0\xB5\xD0\xB2\xD0\xB5\xD1\x80\xD0\xBD\xD1\x8B\xD0\xB9 \xD1\x84\xD0\xBE\xD1\x80\xD0\xBC\xD0\xB0\xD1\x82 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB0. \xD0\x9E\xD0\xB6\xD0\xB8\xD0\xB4\xD0\xB0\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F: CR1M-XXXX-XXXX-XXXX\n"));
    } else if (st == ActivateStatus::NotFound) {
        ConPrint(TR("  [X] License key not found. Please check for typos and try again.\n",
                    "  [X] \xD0\x9A\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBD\xD0\xB5 \xD0\xBD\xD0\xB0\xD0\xB9\xD0\xB4\xD0\xB5\xD0\xBD. \xD0\x9F\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xBE\xD0\xBF\xD0\xB5\xD1\x87\xD0\xB0\xD1\x82\xD0\xBA\xD0\xB8 \xD0\xB8 \xD0\xBF\xD0\xBE\xD0\xBF\xD1\x80\xD0\xBE\xD0\xB1\xD1\x83\xD0\xB9\xD1\x82\xD0\xB5 \xD1\x81\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xB0.\n"));
    } else if (st == ActivateStatus::HwidMismatch) {
        ConPrint(TR("  [X] This license key is already bound to another PC.\n"
                    "      If you upgraded your hardware, contact support@cr1m.net.\n",
                    "  [X] \xD0\xAD\xD1\x82\xD0\xBE\xD1\x82 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD1\x83\xD0\xB6\xD0\xB5 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB7\xD0\xB0\xD0\xBD \xD0\xBA \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xBE\xD0\xBC\xD1\x83 \xD0\x9F\xD0\x9A.\n"
                    "      \xD0\x95\xD1\x81\xD0\xBB\xD0\xB8 \xD0\xB2\xD1\x8B \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xBA\xD0\xBE\xD0\xBC\xD0\xBF\xD0\xBB\xD0\xB5\xD0\xBA\xD1\x82\xD1\x83\xD1\x8E\xD1\x89\xD0\xB8\xD0\xB5, \xD0\xBD\xD0\xB0\xD0\xBF\xD0\xB8\xD1\x88\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xBD\xD0\xB0 support@cr1m.net.\n"));
    } else if (st == ActivateStatus::Revoked) {
        ConPrint(TR("  [X] This license key has been revoked. Contact support@cr1m.net for help.\n",
                    "  [X] \xD0\xAD\xD1\x82\xD0\xBE\xD1\x82 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBE\xD1\x82\xD0\xBE\xD0\xB7\xD0\xB2\xD0\xB0\xD0\xBD. \xD0\x94\xD0\xBB\xD1\x8F \xD0\xBF\xD0\xBE\xD0\xBC\xD0\xBE\xD1\x89\xD0\xB8 \xD0\xBD\xD0\xB0\xD0\xBF\xD0\xB8\xD1\x88\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xBD\xD0\xB0 support@cr1m.net.\n"));
    } else if (st == ActivateStatus::RateLimited) {
        ConPrint(TR("  [X] Too many activation attempts. Please wait 1 minute and try again.\n",
                    "  [X] \xD0\xA1\xD0\xBB\xD0\xB8\xD1\x88\xD0\xBA\xD0\xBE\xD0\xBC \xD0\xBC\xD0\xBD\xD0\xBE\xD0\xB3\xD0\xBE \xD0\xBF\xD0\xBE\xD0\xBF\xD1\x8B\xD1\x82\xD0\xBE\xD0\xBA \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8. \xD0\x9F\xD0\xBE\xD0\xB4\xD0\xBE\xD0\xB6\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 1 \xD0\xBC\xD0\xB8\xD0\xBD\xD1\x83\xD1\x82\xD1\x83 \xD0\xB8 \xD0\xBF\xD0\xBE\xD0\xB2\xD1\x82\xD0\xBE\xD1\x80\xD0\xB8\xD1\x82\xD0\xB5.\n"));
    } else if (st == ActivateStatus::NetworkError) {
        ConPrint(TR("  [X] Could not connect to ",
                    "  [X] \xD0\x9D\xD0\xB5 \xD1\x83\xD0\xB4\xD0\xB0\xD0\xBB\xD0\xBE\xD1\x81\xD1\x8C \xD0\xBF\xD0\xBE\xD0\xB4\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD1\x8C\xD1\x81\xD1\x8F \xD0\xBA ") +
                 std::string(CR1M_API_HOST) +
                 TR(" for first-time activation.\n"
                    "      Check your internet connection / VPN and try again (future launches work offline).\n",
                    " \xD0\xB4\xD0\xBB\xD1\x8F \xD0\xBF\xD0\xB5\xD1\x80\xD0\xB2\xD0\xB8\xD1\x87\xD0\xBD\xD0\xBE\xD0\xB9 \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8.\n"
                    "      \xD0\x9F\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xB8\xD0\xBD\xD1\x82\xD0\xB5\xD1\x80\xD0\xBD\xD0\xB5\xD1\x82 / VPN \xD0\xB8 \xD0\xBF\xD0\xBE\xD0\xB2\xD1\x82\xD0\xBE\xD1\x80\xD0\xB8\xD1\x82\xD0\xB5 \xD0\xBF\xD0\xBE\xD0\xBF\xD1\x8B\xD1\x82\xD0\xBA\xD1\x83 (\xD0\xB4\xD0\xB0\xD0\xBB\xD1\x8C\xD0\xBD\xD0\xB5\xD0\xB9\xD1\x88\xD0\xB8\xD0\xB5 \xD0\xB7\xD0\xB0\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA\xD0\xB8 \xD1\x80\xD0\xB0\xD0\xB1\xD0\xBE\xD1\x82\xD0\xB0\xD1\x8E\xD1\x82 \xD0\xBE\xD1\x84\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD).\n"));
    } else if (st == ActivateStatus::BadSignature) {
        ConPrint(TR("  [X] License signature verification failed. Ensure you are running the official build from cr1m.net.\n",
                    "  [X] \xD0\x9E\xD1\x88\xD0\xB8\xD0\xB1\xD0\xBA\xD0\xB0 \xD0\xBF\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD0\xBA\xD0\xB8 \xD1\x86\xD0\xB8\xD1\x84\xD1\x80\xD0\xBE\xD0\xB2\xD0\xBE\xD0\xB9 \xD0\xBF\xD0\xBE\xD0\xB4\xD0\xBF\xD0\xB8\xD1\x81\xD0\xB8 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8. \xD0\x98\xD1\x81\xD0\xBF\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xB7\xD1\x83\xD0\xB9\xD1\x82\xD0\xB5 \xD0\xBE\xD1\x84\xD0\xB8\xD1\x86\xD0\xB8\xD0\xB0\xD0\xBB\xD1\x8C\xD0\xBD\xD1\x83\xD1\x8E \xD1\x81\xD0\xB1\xD0\xBE\xD1\x80\xD0\xBA\xD1\x83 \xD1\x81 cr1m.net.\n"));
    } else {
        ConPrint(TR("  [X] Activation server temporarily unavailable. Please try again in a moment.\n",
                    "  [X] \xD0\xA1\xD0\xB5\xD1\x80\xD0\xB2\xD0\xB5\xD1\x80 \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB8 \xD0\xB2\xD1\x80\xD0\xB5\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xBD\xD0\xBE \xD0\xBD\xD0\xB5\xD0\xB4\xD0\xBE\xD1\x81\xD1\x82\xD1\x83\xD0\xBF\xD0\xB5\xD0\xBD. \xD0\x9F\xD0\xBE\xD0\xBF\xD1\x80\xD0\xBE\xD0\xB1\xD1\x83\xD0\xB9\xD1\x82\xD0\xB5 \xD1\x87\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7 \xD0\xBD\xD0\xB5\xD1\x81\xD0\xBA\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBA\xD0\xBE \xD1\x81\xD0\xB5\xD0\xBA\xD1\x83\xD0\xBD\xD0\xB4.\n"));
    }
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::optional<AuthProof> EnsureAuthOrTrial(bool nonInteractive, AuthSession& outAuth) {
    outAuth = AuthSession{};
    HwidBundle hb = ComputeHwidBundle();
    outAuth.hb = hb;
    outAuth.trialKeyId = hb.physTrialId;

    std::string licDir = GetAppDataBaseDir();
    std::string licPath = licDir + "\\license.key";

    std::string activeKey;
    bool wasRevoked = false;
    if (auto proof = TryLoadOrActivateKeyFile(hb, licPath, licDir, licPath, nonInteractive, activeKey, wasRevoked)) {
        outAuth.licensed = true;
        outAuth.licenseKey = activeKey;
        return proof;
    }
    if (wasRevoked) return std::nullopt;

    std::string keyCandidates[2] = { GetExeDirA() + "\\license.key", "license.key" };
    for (const auto& kp : keyCandidates) {
        if (kp == licPath) continue;
        if (auto proof = TryLoadOrActivateKeyFile(hb, kp, licDir, licPath, nonInteractive, activeKey, wasRevoked)) {
            outAuth.licensed = true;
            outAuth.licenseKey = activeKey;
            return proof;
        }
        if (wasRevoked) return std::nullopt;
    }

    bool clockTampered = false;
    bool spoofBlocked = false;
    TrialPayload tp = LoadAndReconcileTrial(hb, clockTampered, spoofBlocked);
    bool trialBlocked = clockTampered || spoofBlocked;
    uint64_t remaining = (tp.flags & 1u) || tp.usedSeconds >= TRIAL_BUDGET_SECONDS
        ? 0
        : (TRIAL_BUDGET_SECONDS - tp.usedSeconds);

    if (remaining > 0 && !trialBlocked) {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        ConPrint(TR("\n  [!] NO LICENSE FOUND - 15-MINUTE FREE TEST DRIVE AVAILABLE\n",
                    "\n  [!] \xD0\x9B\xD0\x98\xD0\xA6\xD0\x95\xD0\x9D\xD0\x97\xD0\x98\xD0\xAF \xD0\x9D\xD0\x95 \xD0\x9D\xD0\x90\xD0\x99\xD0\x94\xD0\x95\xD0\x9D\xD0\x90 \xE2\x80\x94 \xD0\x94\xD0\x9E\xD0\xA1\xD0\xA2\xD0\xA3\xD0\x9F\xD0\x95\xD0\x9D \xD0\x91\xD0\x95\xD0\xA1\xD0\x9F\xD0\x9B\xD0\x90\xD0\xA2\xD0\x9D\xD0\xAB\xD0\x99 \xD0\xA2\xD0\x95\xD0\xA1\xD0\xA2-\xD0\x94\xD0\xA0\xD0\x90\xD0\x99\xD0\x92 (15 \xD0\x9C\xD0\x98\xD0\x9D)\n"));
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        {
            std::ostringstream os;
            os << TR("  Test Drive Time Remaining : ",
                     "  \xD0\x9E\xD1\x81\xD1\x82\xD0\xB0\xD0\xBB\xD0\xBE\xD1\x81\xD1\x8C \xD1\x82\xD0\xB5\xD1\x81\xD1\x82-\xD0\xB4\xD1\x80\xD0\xB0\xD0\xB9\xD0\xB2\xD0\xB0      : ")
               << std::setw(2) << std::setfill('0') << (remaining / 60) << ":"
               << std::setw(2) << std::setfill('0') << (remaining % 60)
               << TR(" (15:00 max)\n", " (\xD0\xBC\xD0\xB0\xD0\xBA\xD1\x81. 15:00)\n");
            ConPrint(os.str());
        }
        ConPrint(TR("  Get a full license key at : https://cr1m.net/test-drive\n",
                    "  \xD0\x9F\xD0\xBE\xD0\xBB\xD1\x83\xD1\x87\xD0\xB8\xD1\x82\xD1\x8C \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8    : https://cr1m.net/test-drive\n"));

        if (!nonInteractive) {
            for (;;) {
                ConPrint(TR("\n  Press [ENTER] for Free Test Drive, paste your CR1M-XXXX-XXXX-XXXX key, or type EXIT: ",
                            "\n  \xD0\x9D\xD0\xB0\xD0\xB6\xD0\xBC\xD0\xB8\xD1\x82\xD0\xB5 [ENTER] \xD0\xB4\xD0\xBB\xD1\x8F \xD1\x82\xD0\xB5\xD1\x81\xD1\x82-\xD0\xB4\xD1\x80\xD0\xB0\xD0\xB9\xD0\xB2\xD0\xB0, \xD0\xB2\xD1\x81\xD1\x82\xD0\xB0\xD0\xB2\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 CR1M-XXXX-XXXX-XXXX \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB2\xD0\xB2\xD0\xB5\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 EXIT: "));
                std::string line;
                if (!std::getline(std::cin, line)) return std::nullopt;
                std::string trimmed = Trim(line);
                if (trimmed.empty()) break;

                std::string up = ToUpperAscii(trimmed);
                if (up == "EXIT" || trimmed == "\xD0\x92\xD0\xAB\xD0\xA5\xD0\x9E\xD0\x94" ||
                    trimmed == "\xD0\xB2\xD1\x8B\xD1\x85\xD0\xBE\xD0\xB4") {
                    return std::nullopt;
                }

                std::string normKey = NormalizeLicenseKeyPaste(trimmed);
                if (!IsValidLicenseKeyFormat(normKey)) {
                    PrintActivationError(ActivateStatus::InvalidFormat);
                    continue;
                }
                if (!ConfirmSpooferBeforeBind(hb, nonInteractive)) continue;

                ConPrint(TR("  [*] Activating license key online...\n",
                            "  [*] \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB0 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBE\xD0\xBD\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD...\n"));
                std::optional<AuthProof> proof;
                ActivateStatus st = ActivateLicenseKeyOnline(hb, normKey, licDir, licPath, activeKey, proof);
                if (st == ActivateStatus::Ok && proof) {
                    SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    ConPrint(TR("  [OK] License activated & bound to this PC! Future launches work offline.\n\n",
                                "  [OK] \xD0\x9B\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD1\x8F \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xB8 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB7\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xBA \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC\xD1\x83 \xD0\x9F\xD0\x9A! \xD0\x94\xD0\xB0\xD0\xBB\xD1\x8C\xD1\x88\xD0\xB5 \xD1\x80\xD0\xB0\xD0\xB1\xD0\xBE\xD1\x82\xD0\xB0\xD0\xB5\xD1\x82 \xD0\xBE\xD1\x84\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD.\n\n"));
                    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    outAuth.licensed = true;
                    outAuth.licenseKey = activeKey;
                    return proof;
                }
                PrintActivationError(st);
            }
        }

        auto trialProof = ActivateTrialTokenFromPub();
        if (!trialProof) return std::nullopt;
        outAuth.trialActive = true;
        outAuth.trialUsedSec = tp.usedSeconds;
        outAuth.trialRemainingSec = remaining;
        outAuth.maxWallSec = tp.maxWallSec;
        outAuth.firstWallSec = tp.firstWallSec;
        return trialProof;
    }

    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    if (clockTampered) {
        ConPrint(TR("\n  [!] TEST DRIVE BLOCKED (TIME TAMPER DETECTED) - LICENSE ACTIVATION REQUIRED\n",
                    "\n  [!] \xD0\xA2\xD0\x95\xD0\xA1\xD0\xA2-\xD0\x94\xD0\xA0\xD0\x90\xD0\x99\xD0\x92 \xD0\x97\xD0\x90\xD0\x91\xD0\x9B\xD0\x9E\xD0\x9A\xD0\x98\xD0\xA0\xD0\x9E\xD0\x92\xD0\x90\xD0\x9D (\xD0\x9F\xD0\x9E\xD0\x94\xD0\x9C\xD0\x95\xD0\x9D\xD0\x90 \xD0\x92\xD0\xA0\xD0\x95\xD0\x9C\xD0\x95\xD0\x9D\xD0\x98) \xE2\x80\x94 \xD0\xA2\xD0\xA0\xD0\x95\xD0\x91\xD0\xA3\xD0\x95\xD0\xA2\xD0\xA1\xD0\xAF \xD0\x9B\xD0\x98\xD0\xA6\xD0\x95\xD0\x9D\xD0\x97\xD0\x98\xD0\xAF\n"));
    } else if (spoofBlocked) {
        ConPrint(TR("\n  [!] TEST DRIVE BLOCKED (HWID SPOOFER / HARDWARE DRIFT DETECTED) - LICENSE ACTIVATION REQUIRED\n",
                    "\n  [!] \xD0\xA2\xD0\x95\xD0\xA1\xD0\xA2-\xD0\x94\xD0\xA0\xD0\x90\xD0\x99\xD0\x92 \xD0\x97\xD0\x90\xD0\x91\xD0\x9B\xD0\x9E\xD0\x9A\xD0\x98\xD0\xA0\xD0\x9E\xD0\x92\xD0\x90\xD0\x9D (\xD0\xA1\xD0\x9F\xD0\xA3\xD0\xA4\xD0\x95\xD0\xA0 / \xD0\x9F\xD0\x9E\xD0\x94\xD0\x9C\xD0\x95\xD0\x9D\xD0\x90 \xD0\x9E\xD0\x91\xD0\x9E\xD0\xA0\xD0\xA3\xD0\x94\xD0\x9E\xD0\x92\xD0\x90\xD0\x9D\xD0\x98\xD0\xAF) \xE2\x80\x94 \xD0\xA2\xD0\xA0\xD0\x95\xD0\x91\xD0\xA3\xD0\x95\xD0\xA2\xD0\xA1\xD0\xAF \xD0\x9B\xD0\x98\xD0\xA6\xD0\x95\xD0\x9D\xD0\x97\xD0\x98\xD0\xAF\n"));
    } else {
        ConPrint(TR("\n  [!] 15-MINUTE FREE TEST DRIVE EXPIRED - LICENSE ACTIVATION REQUIRED\n",
                    "\n  [!] 15-\xD0\x9C\xD0\x98\xD0\x9D\xD0\xA3\xD0\xA2\xD0\x9D\xD0\xAB\xD0\x99 \xD0\xA2\xD0\x95\xD0\xA1\xD0\xA2-\xD0\x94\xD0\xA0\xD0\x90\xD0\x99\xD0\x92 \xD0\x97\xD0\x90\xD0\x92\xD0\x95\xD0\xA0\xD0\xA8\xD0\x81\xD0\x9D \xE2\x80\x94 \xD0\xA2\xD0\xA0\xD0\x95\xD0\x91\xD0\xA3\xD0\x95\xD0\xA2\xD0\xA1\xD0\xAF \xD0\x90\xD0\x9A\xD0\xA2\xD0\x98\xD0\x92\xD0\x90\xD0\xA6\xD0\x98\xD0\xAF \xD0\x9B\xD0\x98\xD0\xA6\xD0\x95\xD0\x9D\xD0\x97\xD0\x98\xD0\x98\n"));
    }
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    ConPrint(TR("  Get your license key at: https://cr1m.net/test-drive\n",
                "  \xD0\x9F\xD0\xBE\xD0\xBB\xD1\x83\xD1\x87\xD0\xB8\xD1\x82\xD1\x8C \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBC\xD0\xBE\xD0\xB6\xD0\xBD\xD0\xBE \xD0\xBD\xD0\xB0: https://cr1m.net/test-drive\n"));

    if (nonInteractive) return std::nullopt;

    for (;;) {
        ConPrint(TR("\n  Paste your CR1M-XXXX-XXXX-XXXX License Key (or type EXIT): ",
                    "\n  \xD0\x92\xD1\x81\xD1\x82\xD0\xB0\xD0\xB2\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 CR1M-XXXX-XXXX-XXXX (\xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB2\xD0\xB2\xD0\xB5\xD0\xB4\xD0\xB8\xD1\x82\xD0\xB5 EXIT): "));
        std::string inKey;
        if (!std::getline(std::cin, inKey)) return std::nullopt;
        std::string trimmed = Trim(inKey);
        if (trimmed.empty()) continue;

        std::string up = ToUpperAscii(trimmed);
        if (up == "EXIT" || trimmed == "\xD0\x92\xD0\xAB\xD0\xA5\xD0\x9E\xD0\x94" ||
            trimmed == "\xD0\xB2\xD1\x8B\xD1\x85\xD0\xBE\xD0\xB4") {
            return std::nullopt;
        }

        std::string normKey = NormalizeLicenseKeyPaste(trimmed);
        if (!IsValidLicenseKeyFormat(normKey)) {
            PrintActivationError(ActivateStatus::InvalidFormat);
            continue;
        }
        if (!ConfirmSpooferBeforeBind(hb, nonInteractive)) continue;

        ConPrint(TR("  [*] Activating license key online...\n",
                    "  [*] \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB0 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBE\xD0\xBD\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD...\n"));
        std::optional<AuthProof> proof;
        ActivateStatus st = ActivateLicenseKeyOnline(hb, normKey, licDir, licPath, activeKey, proof);
        if (st == ActivateStatus::Ok && proof) {
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("  [OK] License activated & bound to this PC! Future launches work offline.\n\n",
                        "  [OK] \xD0\x9B\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD1\x8F \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB8\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xB8 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB7\xD0\xB0\xD0\xBD\xD0\xB0 \xD0\xBA \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC\xD1\x83 \xD0\x9F\xD0\x9A! \xD0\x94\xD0\xB0\xD0\xBB\xD1\x8C\xD1\x88\xD0\xB5 \xD1\x80\xD0\xB0\xD0\xB1\xD0\xBE\xD1\x82\xD0\xB0\xD0\xB5\xD1\x82 \xD0\xBE\xD1\x84\xD0\xBB\xD0\xB0\xD0\xB9\xD0\xBD.\n\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            outAuth.licensed = true;
            outAuth.licenseKey = activeKey;
            return proof;
        }
        PrintActivationError(st);
    }
}

} // namespace cr1m
