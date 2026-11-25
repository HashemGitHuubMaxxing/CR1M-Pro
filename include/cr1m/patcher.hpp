// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/aob.hpp"
#include "cr1m/auth_proof.hpp"
#include "cr1m/build_config.hpp"
#include <cstdint>
#include <vector>

namespace cr1m {

using SigManifestProvider = bool (*)(bool is64, bool allowNetwork, SignedSigManifest& outManifest);

void ApplySystemPerformanceOptimizations(HANDLE hProc, DWORD pid, ModSessionState* sess = nullptr);
void RevertModEffects(ModSessionState& sess);

bool ApplyPatchesX64(HANDLE hp, uintptr_t base, const std::vector<uint8_t>& txt, uint32_t txtRva,
                     const Kernel32Iat& iat, uint32_t targetFps, PatchReport& report,
                     const AuthProof& proof, ModSessionState* sess = nullptr,
                     const RdataSlice* rdata = nullptr,
                     SigManifestProvider manifestProvider = nullptr);

bool ApplyPatchesX86(HANDLE hp, uintptr_t base, const std::vector<uint8_t>& txt, uint32_t txtRva,
                     const Kernel32Iat& iat, uint32_t targetFps, PatchReport& report,
                     const AuthProof& proof, ModSessionState* sess = nullptr,
                     const RdataSlice* rdata = nullptr,
                     SigManifestProvider manifestProvider = nullptr);

} // namespace cr1m
