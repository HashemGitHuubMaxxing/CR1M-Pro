// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>

namespace cr1m {

struct HwidBundle;
class AuthProof;

std::optional<AuthProof> VerifySignedReceipt(
    const HwidBundle& hb,
    const std::string& receiptText,
    std::string& outLicenseKey,
    std::string* outIssuedAt = nullptr);

std::optional<AuthProof> ActivateTrialTokenFromPub();

namespace detail {

// Embedded 2048 bit RSA Public Key (BCRYPT_RSAPUBLIC_BLOB: public key only, zero private secrets)
inline constexpr std::array<uint8_t, 283> kRsaPubBlob = {
    0x52, 0x53, 0x41, 0x31, 0x00, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xfe, 0x53, 0x54, 0x1d, 0xd8,
    0xde, 0x18, 0x1b, 0x55, 0xf8, 0x45, 0xc7, 0x81, 0x74, 0xc5, 0x9f, 0x68, 0x8f, 0xe0, 0xd9, 0x95,
    0x88, 0xd5, 0xad, 0xa8, 0x1c, 0xf2, 0xd7, 0x91, 0x28, 0xa6, 0xe6, 0x22, 0x61, 0xe3, 0xc0, 0xa4,
    0x21, 0x03, 0x72, 0x4d, 0xb2, 0x37, 0x34, 0xa2, 0x0a, 0x30, 0x52, 0x05, 0x17, 0x3c, 0x0e, 0xb8,
    0xa6, 0xc4, 0xc2, 0xaf, 0xf7, 0x70, 0x36, 0xbe, 0x2d, 0x92, 0x3c, 0x5a, 0x82, 0x20, 0x12, 0x42,
    0x46, 0x54, 0x38, 0x07, 0x28, 0xab, 0xba, 0x4a, 0x06, 0xe7, 0x5c, 0x2f, 0x1a, 0xd4, 0x68, 0xfb,
    0x0c, 0xff, 0xfc, 0x6b, 0xc7, 0xff, 0x1a, 0x2e, 0xfc, 0x9a, 0xe3, 0x86, 0x5e, 0x79, 0xca, 0x25,
    0xe0, 0x4a, 0x3d, 0xc6, 0xd3, 0x95, 0x43, 0x58, 0x89, 0x70, 0x25, 0x68, 0x6d, 0x07, 0xa1, 0x09,
    0x77, 0xc2, 0xc4, 0xd6, 0xfe, 0xe5, 0xfe, 0xd7, 0x42, 0x1a, 0xbb, 0x23, 0xe5, 0xf8, 0xaf, 0xbc,
    0x4a, 0xa2, 0x55, 0x79, 0x60, 0xd5, 0x13, 0xce, 0xcb, 0xe9, 0x81, 0x87, 0x4d, 0x61, 0x24, 0xf1,
    0x51, 0x18, 0x1c, 0x05, 0xb6, 0xb0, 0x0e, 0xad, 0x1f, 0xa3, 0x60, 0x4f, 0x46, 0xba, 0xf0, 0x47,
    0x4e, 0x53, 0x9c, 0x63, 0x71, 0xfb, 0x6a, 0x75, 0x66, 0x19, 0xa3, 0x84, 0xab, 0x77, 0x70, 0xd7,
    0x3a, 0x1c, 0x72, 0x7b, 0x8b, 0x70, 0xb8, 0x63, 0xba, 0xc0, 0x35, 0x80, 0x17, 0xd9, 0xae, 0x63,
    0xe6, 0x64, 0x77, 0x36, 0x21, 0x17, 0xb3, 0x9b, 0x71, 0x5d, 0xe3, 0xcc, 0xb4, 0x22, 0xeb, 0xa7,
    0x10, 0x1b, 0x62, 0x85, 0x8c, 0xc9, 0xef, 0xed, 0x07, 0x20, 0xb9, 0x98, 0x1a, 0xc1, 0x4c, 0x45,
    0xd7, 0x35, 0x50, 0x4f, 0x05, 0x0f, 0xa7, 0x42, 0x34, 0x80, 0x3f, 0x59, 0x93, 0x31, 0x00, 0x43,
    0xb5, 0xbf, 0x35, 0x81, 0xf9, 0x83, 0x9d, 0xfe, 0x71, 0x52, 0x09
};

constexpr uint64_t ComputeFnv1a64(std::span<const uint8_t> bytes) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (uint8_t b : bytes) {
        h ^= b;
        h *= 0x100000001B3ULL;
    }
    return h;
}

consteval uint64_t ExpectedPubKeyHash() noexcept {
    return ComputeFnv1a64(std::span<const uint8_t>(kRsaPubBlob));
}

inline constexpr uint64_t kPubMask   = 0x6D4F2E91A8C35B17ULL;
inline constexpr uint64_t kTokSalt   = 0x93E71C54B0D28A4FULL;
inline constexpr uint64_t kTrialSalt = 0x4A7E29C1D3F8605BULL;
inline constexpr uint64_t kExpPubX   = ExpectedPubKeyHash() ^ kPubMask;

} // namespace detail

// Move only authorization capability token (never default constructible).
// Only VerifySignedReceipt() and ActivateTrialTokenFromPub() may mint a valid AuthProof.
class AuthProof final {
public:
    static constexpr uint32_t kCaveMagic = 0x354D5243u; // "CRM5"

    AuthProof() = delete;
    AuthProof(const AuthProof&) = delete;
    AuthProof& operator=(const AuthProof&) = delete;

    AuthProof(AuthProof&& other) noexcept
        : tokenTag_(other.tokenTag_), trialMode_(other.trialMode_), leaseSec_(other.leaseSec_) {
        other.revoke();
    }

    AuthProof& operator=(AuthProof&& other) noexcept {
        if (this != &other) {
            revoke();
            tokenTag_  = other.tokenTag_;
            trialMode_ = other.trialMode_;
            leaseSec_  = other.leaseSec_;
            other.revoke();
        }
        return *this;
    }

    ~AuthProof() { revoke(); }

    [[nodiscard]] bool isValid() const noexcept {
        const uint64_t expected = detail::kExpPubX ^ detail::kPubMask;
        if (!trialMode_) {
            return (tokenTag_ ^ detail::kTokSalt) == expected;
        }
        return (tokenTag_ ^ detail::kTrialSalt) == expected;
    }

    [[nodiscard]] bool isTrial() const noexcept {
        return isValid() && trialMode_;
    }

    [[nodiscard]] uint32_t deriveCaveMagic() const noexcept {
        return isValid() ? kCaveMagic : 0u;
    }

    [[nodiscard]] uint32_t channelId() const noexcept {
        return isValid() ? kBuildChannelId : 0u;
    }

    [[nodiscard]] uint64_t computeInitialLeaseQpc(uint64_t nowQpc, uint64_t freqQpc) const noexcept {
        if (!isValid()) return 1ULL;
        if (!trialMode_) return 0ULL;
        return nowQpc + leaseSec_ * freqQpc;
    }

    void revoke() noexcept {
        volatile uint64_t* t = &tokenTag_;
        *t = 0;
        trialMode_ = false;
        leaseSec_  = 0;
    }

private:
    explicit AuthProof(uint64_t tokenTag, bool trialMode, uint64_t leaseSec) noexcept
        : tokenTag_(tokenTag), trialMode_(trialMode), leaseSec_(leaseSec) {}

    uint64_t tokenTag_ = 0;
    bool     trialMode_ = false;
    uint64_t leaseSec_  = 0;

    friend std::optional<AuthProof> VerifySignedReceipt(
        const HwidBundle& hb,
        const std::string& receiptText,
        std::string& outLicenseKey,
        std::string* outIssuedAt);
    friend std::optional<AuthProof> ActivateTrialTokenFromPub();
};

static_assert(!std::is_default_constructible_v<AuthProof>,
              "AuthProof must never be default-constructible.");
static_assert(!std::is_copy_constructible_v<AuthProof>,
              "AuthProof must be move-only.");

} // namespace cr1m
