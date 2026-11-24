// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/auth_proof.hpp"
#include "cr1m/build_config.hpp"
#include "cr1m/hwid.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace cr1m {

struct AuthSession {
    bool licensed = false;
    bool trialActive = false;
    uint64_t trialUsedSec = 0;
    uint64_t trialRemainingSec = 0;
    uint64_t maxWallSec = 0;
    uint64_t firstWallSec = 0;
    std::string licenseKey;
    std::string trialKeyId;
    HwidBundle hb;
};

enum class ActivateStatus {
    Ok = 0,
    InvalidFormat,
    NotFound,
    HwidMismatch,
    Revoked,
    RateLimited,
    NetworkError,
    ServerError,
    BadSignature
};

bool ComputeSha256(BCRYPT_ALG_HANDLE hShaAlg, const void* data, size_t len, BYTE* outHash);
bool ComputeSha256Bytes(const void* data, size_t len, BYTE outHash[32]);
bool ComputeLocalSiliconHwidHash(const HwidBundle& hb, std::string& outLowerHex);

bool HttpsPostJson(const std::wstring& host, const std::wstring& path,
                   const std::string& jsonBody, DWORD connectMs, DWORD rwMs,
                   DWORD& outHttpCode, std::string& outRespBody);

bool VerifyRsaSha256WithEmbeddedPub(const std::string& payload,
                                    const std::string& sigHex,
                                    uint64_t* outPubHash);

std::optional<AuthProof> VerifySignedReceipt(const HwidBundle& hb,
                                             const std::string& receiptText,
                                             std::string& outLicenseKey,
                                             std::string* outIssuedAt);

bool CheckLicenseRevocationFailOpen(const HwidBundle& hb,
                                    const std::string& licenseKey,
                                    const std::string& receiptIssuedAt,
                                    const std::string& licDir,
                                    const std::string& cachedLicPath,
                                    const std::string& sourceFilePath);

ActivateStatus ActivateLicenseKeyOnline(const HwidBundle& hb,
                                        const std::string& rawInput,
                                        const std::string& licDir,
                                        const std::string& licPath,
                                        std::string& outLicenseKey,
                                        std::optional<AuthProof>& outProof);

void PrintActivationError(ActivateStatus st);

std::optional<AuthProof> EnsureAuthOrTrial(bool nonInteractive, AuthSession& outAuth);

} // namespace cr1m
