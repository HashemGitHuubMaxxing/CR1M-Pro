// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#if !defined(_WIN64) || !defined(__x86_64__)
#error "CR1M Pro Mod requires an x86_64 Windows target."
#endif

#if !defined(__clang__) || !defined(__MINGW64__)
#error "CR1M Pro Mod requires the x86_64 MinGW-w64 Clang toolchain (x86_64-w64-windows-gnu)."
#endif

#if __cplusplus < 202002L
#error "CR1M Pro Mod requires C++20 (-std=c++20)."
#endif

#ifndef CR1M_API_HOST_RAW
#error "CR1M_API_HOST_RAW must be defined at compile time."
#endif

#ifndef CR1M_BUILD_CHANNEL
#error "CR1M_BUILD_CHANNEL must be defined at compile time."
#endif

static_assert(CR1M_BUILD_CHANNEL >= 1 && CR1M_BUILD_CHANNEL <= 3,
              "CR1M_BUILD_CHANNEL must be between 1 and 3.");

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <bcrypt.h>
#include <cstdint>

#define CR1M_STR2(x)  #x
#define CR1M_STR(x)   CR1M_STR2(x)
#define CR1M_WIDE2(s) L##s
#define CR1M_WIDE(s)  CR1M_WIDE2(s)

#define CR1M_API_HOST   CR1M_STR(CR1M_API_HOST_RAW)
#define CR1M_API_HOST_W CR1M_WIDE(CR1M_STR(CR1M_API_HOST_RAW))

static_assert(sizeof(CR1M_API_HOST) > 4,
              "CR1M_API_HOST_RAW must specify a valid hostname.");

#ifndef PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
#define PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION 0x4
#endif

namespace cr1m {

inline constexpr uint32_t kBuildChannelId = static_cast<uint32_t>(CR1M_BUILD_CHANNEL);
inline constexpr const char* kBuildChannelLabel =
    (kBuildChannelId == 1u) ? "Release" :
    (kBuildChannelId == 2u) ? "Beta" : "Internal";

using pfnSetProcessInformation      = BOOL (WINAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);
using pfnIsWow64Process2            = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
using pfnGetPackagesByPackageFamily = LONG (WINAPI*)(PCWSTR, UINT32*, PWSTR*, UINT32*, WCHAR*);

} // namespace cr1m
