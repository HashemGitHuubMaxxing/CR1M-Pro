// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/auth.hpp"
#include "cr1m/auth_proof.hpp"
#include "cr1m/build_config.hpp"
#include "cr1m/hwid.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cr1m {

struct ModSessionState;
struct Kernel32Iat;

inline constexpr uint64_t TRIAL_BUDGET_SECONDS = 15ULL * 60ULL;
inline constexpr uint32_t TRIAL_BLOB_HDR_MAGIC = 0x31445443u; // "CTD1"
inline constexpr uint32_t TRIAL_PAYLOAD_MAGIC  = 0x44545243u; // "CRTD"

#pragma pack(push, 1)
struct TrialPayload {
    uint32_t magic;
    uint32_t version;
    uint64_t usedSeconds;
    uint64_t firstWallSec;
    uint64_t maxWallSec;
    uint64_t lastUpSec;
    uint32_t flags; // bit 0 = expired / tampered
    uint32_t reserved;
};
struct TrialDiskBlob {
    uint32_t hdrMagic;
    uint8_t  nonce[8];
    uint8_t  cipher[sizeof(TrialPayload)];
    uint8_t  mac[16];
};
#pragma pack(pop)

uint64_t GetUnixUtcSeconds();
uint64_t QueryNetUtcSeconds();
uint64_t ReadNetWallLatest();
void     UpdateNetWallLatest(uint64_t utcSec);
void     StartAsyncNetUtcCheck(HANDLE& hThread);
void     FinishAsyncNetUtcCheck(HANDLE& hThread, DWORD waitMs = 1200);

void         SaveTrialAnchors(const std::string& trialKeyId, const TrialPayload& pl);
TrialPayload LoadAndReconcileTrial(const HwidBundle& hb, bool& outClockTampered, bool& outSpoofBlocked);

std::optional<AuthProof> ActivateTrialTokenFromPub();

void InitWatchdogCtrlLock();
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);

void RunLiveTrialWatchdog(AuthSession& auth,
                          ModSessionState& sess,
                          AuthProof& proof,
                          const std::vector<uint8_t>& txtBuf,
                          uint32_t textRva,
                          const Kernel32Iat& iat,
                          uint32_t targetFps,
                          bool nonInteractive);

} // namespace cr1m
