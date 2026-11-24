// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/auth_proof.hpp"
#include "cr1m/build_config.hpp"
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <vector>

namespace cr1m {

struct CaveBuilder {
    std::vector<uint8_t> buf;
    explicit CaveBuilder(size_t r = 512) { buf.reserve(r); }
    size_t pos() const { return buf.size(); }
    void u8(uint8_t v) { buf.push_back(v); }
    void u32(uint32_t v) { for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>(v >> (i * 8))); }
    void u64(uint64_t v) { for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>(v >> (i * 8))); }
    void bytes(const std::initializer_list<uint8_t>& il) { buf.insert(buf.end(), il.begin(), il.end()); }
    void padTo(size_t n) { while (buf.size() < n) buf.push_back(0x90); }
    size_t jcc32(uint8_t cc) { u8(0x0F); u8(cc); size_t p = pos(); u32(0); return p; }
    size_t jmp32() { u8(0xE9); size_t p = pos(); u32(0); return p; }
    void patch32(size_t off, size_t target) {
        int32_t d = static_cast<int32_t>(target) - static_cast<int32_t>(off + 4);
        memcpy(&buf[off], &d, 4);
    }
    void rip32(uint32_t dataOff) {
        int32_t disp = static_cast<int32_t>(dataOff) - static_cast<int32_t>(buf.size() + 4);
        u32(static_cast<uint32_t>(disp));
    }
};

std::vector<uint8_t> BuildX64Cave(uint32_t targetFps, uint64_t ticksPerFrame,
                                  uint64_t pIatQpc, uint64_t pIatSleep,
                                  const AuthProof& proof);

std::vector<uint8_t> BuildX86Cave(uint32_t caveBase32, uint32_t targetFps, uint64_t ticksPerFrame,
                                  uint32_t pIatQpc, uint32_t pIatSleep,
                                  uint32_t switchJoinVa,
                                  const AuthProof& proof);

uintptr_t AllocNearModule(HANDLE hp, uintptr_t targetAddr, SIZE_T size);

} // namespace cr1m
