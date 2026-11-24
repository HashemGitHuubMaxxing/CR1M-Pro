// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/vrr.hpp"
#include "cr1m/hwid.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/util.hpp"
#include <dxgi1_6.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace cr1m {

namespace {

// Minimal ADLX C-ABI interfaces verified against GPUOpen ADLX SDK
using FnAdlxRelease     = int (__stdcall*)(void*);
using FnAdlxGetDispSvc  = int (__stdcall*)(void*, void**);
using FnAdlxGetDisplays = int (__stdcall*)(void*, void**);
using FnAdlxListSize    = unsigned int (__stdcall*)(void*);
using FnAdlxListAt      = int (__stdcall*)(void*, unsigned int, void**);
using FnAdlxGetFreeSync = int (__stdcall*)(void*, void*, void**);
using FnAdlxBoolPtr     = int (__stdcall*)(void*, uint8_t*);
using FnAdlxSetBool     = int (__stdcall*)(void*, uint8_t);

#pragma pack(push, 8)
struct NvDrsBinaryTest { uint32_t valueLength; uint8_t valueData[4096]; };
struct NvDrsSettingV1 {
    uint32_t version;
    uint16_t settingName[2048];
    uint32_t settingId;
    uint32_t settingType;
    uint32_t settingLocation;
    uint32_t isCurrentPredefined;
    uint32_t isPredefinedValid;
    union { uint32_t u32PredefinedValue; NvDrsBinaryTest binaryPredefinedValue; uint16_t wszPredefinedValue[2048]; };
    union { uint32_t u32CurrentValue;    NvDrsBinaryTest binaryCurrentValue;    uint16_t wszCurrentValue[2048]; };
};
#pragma pack(pop)

std::wstring ReadWinVrrReg() {
    HKEY hk = NULL;
    std::wstring res;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        wchar_t buf[1024]{};
        DWORD sz = sizeof(buf) - sizeof(wchar_t);
        if (RegQueryValueExW(hk, L"DirectXUserGlobalSettings", NULL, NULL,
                             reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
            res = buf;
        }
        RegCloseKey(hk);
    }
    return res;
}

void EnsureDxToken(std::wstring& cur, const std::wstring& key, const std::wstring& val) {
    size_t pos = cur.find(key + L"=");
    if (pos != std::wstring::npos) {
        size_t end = cur.find(L';', pos);
        if (end != std::wstring::npos) cur.replace(pos, end - pos + 1, key + L"=" + val + L";");
        else cur.replace(pos, cur.size() - pos, key + L"=" + val + L";");
    } else {
        if (!cur.empty() && cur.back() != L';') cur += L";";
        cur += key + L"=" + val + L";";
    }
}

void SetOrAddDxPref(std::wstring& cur, const std::wstring& key, const std::wstring& val, bool keepNonZero) {
    size_t pos = cur.find(key + L"=");
    if (pos != std::wstring::npos) {
        size_t valStart = pos + key.size() + 1;
        size_t end = cur.find(L';', valStart);
        std::wstring existing = (end != std::wstring::npos)
            ? cur.substr(valStart, end - valStart)
            : cur.substr(valStart);
        if (keepNonZero && !existing.empty() && existing != L"0") return;
        if (end != std::wstring::npos) cur.replace(pos, end - pos + 1, key + L"=" + val + L";");
        else cur.replace(pos, cur.size() - pos, key + L"=" + val + L";");
    } else {
        if (!cur.empty() && cur.back() != L';') cur += L";";
        cur += key + L"=" + val + L";";
    }
}

bool EnableWinVrrReg() {
    std::wstring cur = ReadWinVrrReg();
    EnsureDxToken(cur, L"VRROptimizeEnable", L"1");
    EnsureDxToken(cur, L"SwapEffectUpgradeEnable", L"1");

    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences",
                        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS) {
        return false;
    }
    LONG r = RegSetValueExW(hk, L"DirectXUserGlobalSettings", 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(cur.c_str()),
                            static_cast<DWORD>((cur.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

void CheckOrSetAdlxFreeSync(bool applyEnable, bool& outSupported, bool& outEnabled, bool& outChecked) {
    outChecked = false; outSupported = false; outEnabled = false;
    HMODULE adlx = LoadLibraryW(L"amdadlx64.dll");
    if (!adlx) return;
    using FnQVer = int (*)(uint64_t*, const char**);
    using FnInit = int (*)(uint64_t, void**);
    using FnTerm = int (*)();
    auto qv   = reinterpret_cast<FnQVer>(GetProcAddress(adlx, "ADLXQueryFullVersion"));
    auto init = reinterpret_cast<FnInit>(GetProcAddress(adlx, "ADLXInitialize"));
    auto term = reinterpret_cast<FnTerm>(GetProcAddress(adlx, "ADLXTerminate"));
    uint64_t ver = 0; const char* vs = nullptr; void* sys = nullptr;
    if (qv && init && qv(&ver, &vs) == 0 && init(ver, &sys) == 0 && sys) {
        outChecked = true;
        void** sysVtbl = *reinterpret_cast<void***>(sys);
        void* dispSvc = nullptr;
        if (reinterpret_cast<FnAdlxGetDispSvc>(sysVtbl[3])(sys, &dispSvc) == 0 && dispSvc) {
            void** dsVtbl = *reinterpret_cast<void***>(dispSvc);
            void* dispList = nullptr;
            if (reinterpret_cast<FnAdlxGetDisplays>(dsVtbl[4])(dispSvc, &dispList) == 0 && dispList) {
                void** dlVtbl = *reinterpret_cast<void***>(dispList);
                unsigned int cnt = reinterpret_cast<FnAdlxListSize>(dlVtbl[3])(dispList);
                for (unsigned int i = 0; i < cnt; ++i) {
                    void* disp = nullptr;
                    if (reinterpret_cast<FnAdlxListAt>(dlVtbl[11])(dispList, i, &disp) == 0 && disp) {
                        void** dVtbl = *reinterpret_cast<void***>(disp);
                        void* fs = nullptr;
                        if (reinterpret_cast<FnAdlxGetFreeSync>(dsVtbl[9])(dispSvc, disp, &fs) == 0 && fs) {
                            void** fsVtbl = *reinterpret_cast<void***>(fs);
                            uint8_t sup = 0, en = 0;
                            reinterpret_cast<FnAdlxBoolPtr>(fsVtbl[3])(fs, &sup);
                            reinterpret_cast<FnAdlxBoolPtr>(fsVtbl[4])(fs, &en);
                            if (sup) {
                                outSupported = true;
                                if (applyEnable && !en) {
                                    reinterpret_cast<FnAdlxSetBool>(fsVtbl[5])(fs, 1);
                                    reinterpret_cast<FnAdlxBoolPtr>(fsVtbl[4])(fs, &en);
                                }
                                if (en) outEnabled = true;
                            }
                            reinterpret_cast<FnAdlxRelease>(fsVtbl[1])(fs);
                        }
                        reinterpret_cast<FnAdlxRelease>(dVtbl[1])(disp);
                    }
                }
                reinterpret_cast<FnAdlxRelease>(dlVtbl[1])(dispList);
            }
            reinterpret_cast<FnAdlxRelease>(dsVtbl[1])(dispSvc);
        }
        if (term) term();
    }
    FreeLibrary(adlx);
}

void CheckOrSetNvDrsGsync(int actionMode, bool& outChecked, uint32_t& outMode) {
    outChecked = false; outMode = 0;
    HMODULE nv = GetModuleHandleW(L"nvapi64.dll");
    if (!nv) nv = LoadLibraryW(L"nvapi64.dll"); // Retained to avoid driver teardown crash on exit
    if (!nv) return;
    auto qi = reinterpret_cast<void* (__cdecl*)(unsigned int)>(GetProcAddress(nv, "nvapi_QueryInterface"));
    if (!qi) return;
    auto pInit    = reinterpret_cast<int (__cdecl*)()>(qi(0x0150E828));
    auto pCreate  = reinterpret_cast<int (__cdecl*)(void**)>(qi(0x0694D52E));
    auto pLoad    = reinterpret_cast<int (__cdecl*)(void*)>(qi(0x375DBD6B));
    auto pCurGlob = reinterpret_cast<int (__cdecl*)(void*, void**)>(qi(0x617BFF9F));
    auto pGetSet  = reinterpret_cast<int (__cdecl*)(void*, void*, uint32_t, NvDrsSettingV1*)>(qi(0x73BF8338));
    auto pSetSet  = reinterpret_cast<int (__cdecl*)(void*, void*, NvDrsSettingV1*)>(qi(0x577DD202));
    auto pSave    = reinterpret_cast<int (__cdecl*)(void*)>(qi(0xFCBC7E14));
    auto pDestroy = reinterpret_cast<int (__cdecl*)(void*)>(qi(0xDAD9CFD8));
    if (!pInit || pInit() != 0) return;

    void* sess = nullptr; void* prof = nullptr;
    if (pCreate && pLoad && pCurGlob && pCreate(&sess) == 0 && pLoad(sess) == 0 && pCurGlob(sess, &prof) == 0) {
        outChecked = true;
        auto* st = static_cast<NvDrsSettingV1*>(calloc(1, sizeof(NvDrsSettingV1)));
        st->version = static_cast<uint32_t>(sizeof(NvDrsSettingV1) | (1u << 16));
        if (pGetSet && pGetSet(sess, prof, 0x1194F158, st) == 0) {
            outMode = st->u32CurrentValue;
        }
        if (actionMode == 1 && outMode != 2 && pSetSet && pSave) {
            memset(st, 0, sizeof(NvDrsSettingV1));
            st->version = static_cast<uint32_t>(sizeof(NvDrsSettingV1) | (1u << 16));
            st->settingId = 0x1194F158;
            st->settingType = 0;
            st->u32CurrentValue = 2;
            if (pSetSet(sess, prof, st) == 0) {
                memset(st, 0, sizeof(NvDrsSettingV1));
                st->version = static_cast<uint32_t>(sizeof(NvDrsSettingV1) | (1u << 16));
                st->settingId = 0x1094F157;
                st->settingType = 0;
                st->u32CurrentValue = 1;
                pSetSet(sess, prof, st);
                if (pSave(sess) == 0) outMode = 2;
            }
        } else if (actionMode == 2 && outMode != 0 && pSetSet && pSave) {
            memset(st, 0, sizeof(NvDrsSettingV1));
            st->version = static_cast<uint32_t>(sizeof(NvDrsSettingV1) | (1u << 16));
            st->settingId = 0x1194F158;
            st->settingType = 0;
            st->u32CurrentValue = 0;
            pSetSet(sess, prof, st);
            memset(st, 0, sizeof(NvDrsSettingV1));
            st->version = static_cast<uint32_t>(sizeof(NvDrsSettingV1) | (1u << 16));
            st->settingId = 0x1094F157;
            st->settingType = 0;
            st->u32CurrentValue = 0;
            pSetSet(sess, prof, st);
            if (pSave(sess) == 0) outMode = 0;
        }
        free(st);
        if (pDestroy) pDestroy(sess);
    }
}

bool IsIgpuAdapter(UINT vendorId, uint64_t vramMb, const std::string& upperName) {
    if (vendorId == 0x10DE) return false;
    if (vendorId == 0x8086) {
        return !(upperName.find("ARC") != std::string::npos && vramMb > 2048);
    }
    if (vendorId == 0x1002) {
        if (upperName.find("RX ") != std::string::npos || upperName.find("PRO ") != std::string::npos) {
            return false;
        }
        if (vramMb <= 2048) return true;
        static const char* kApuHints[] = {
            "610M", "660M", "680M", "740M", "760M",
            "780M", "880M", "890M", "GRAPHICS", "VEGA"
        };
        for (const char* hint : kApuHints) {
            if (upperName.find(hint) != std::string::npos) return true;
        }
        return false;
    }
    return vramMb <= 1024;
}

void DetectDeviceTopology(VrrAuditResult& vr) {
    int chassis = ReadSmbiosSnapshot().chassisType;
    bool chassisKnown = false;
    bool chassisPortable = false;
    switch (chassis) {
        case 8: case 9: case 10: case 11: case 14: case 30: case 31: case 32:
            chassisKnown = true; chassisPortable = true; break;
        case 3: case 4: case 5: case 6: case 7: case 13: case 15: case 16: case 17: case 35: case 36:
            chassisKnown = true; chassisPortable = false; break;
        default: break;
    }

    SYSTEM_POWER_STATUS sps{};
    bool hasBattery = (GetSystemPowerStatus(&sps) && sps.BatteryFlag != 255 && (sps.BatteryFlag & 128) == 0);
    bool hasIgpu = false, hasDgpu = false;
    bool primaryOnIgpu = false, primaryOnDgpu = false;
    bool hasMobileGpuName = false;

    IDXGIFactory6* f6 = nullptr;
    if (SUCCEEDED(CreateDXGIFactory1(IID_PPV_ARGS(&f6)))) {
        BOOL tearing = FALSE;
        f6->CheckFeatureSupport(DXGI_FEATURE_PRESENT_ALLOW_TEARING, &tearing, sizeof(tearing));
        vr.dxgiAllowTearing = (tearing != FALSE);
        for (UINT i = 0; ; ++i) {
            IDXGIAdapter1* ad = nullptr;
            if (f6->EnumAdapters1(i, &ad) == DXGI_ERROR_NOT_FOUND) break;
            DXGI_ADAPTER_DESC1 d{};
            ad->GetDesc1(&d);
            if (d.VendorId != 0x1414 && !(d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                std::string name = WideToUtf8(d.Description);
                std::string up = ToUpperAscii(name);
                uint64_t vramMb = static_cast<uint64_t>(d.DedicatedVideoMemory / (1024ULL * 1024ULL));
                bool isIgpu = IsIgpuAdapter(d.VendorId, vramMb, up);

                if (d.VendorId == 0x10DE) vr.hasNvidiaGpu = true;
                if (d.VendorId == 0x1002) vr.hasAmdGpu = true;
                if (up.find("LAPTOP") != std::string::npos || up.find("MOBILE") != std::string::npos ||
                    up.find("MAX-Q") != std::string::npos) {
                    hasMobileGpuName = true;
                }
                if (isIgpu) hasIgpu = true; else hasDgpu = true;

                bool ownsPrimary = false;
                for (UINT j = 0; ; ++j) {
                    IDXGIOutput* out = nullptr;
                    if (ad->EnumOutputs(j, &out) == DXGI_ERROR_NOT_FOUND) break;
                    DXGI_OUTPUT_DESC od{};
                    if (SUCCEEDED(out->GetDesc(&od))) {
                        MONITORINFOEXW mi{}; mi.cbSize = sizeof(mi);
                        if (GetMonitorInfoW(od.Monitor, &mi) && (mi.dwFlags & MONITORINFOF_PRIMARY)) {
                            ownsPrimary = true;
                        }
                    }
                    out->Release();
                }
                if (ownsPrimary) {
                    if (isIgpu) primaryOnIgpu = true; else primaryOnDgpu = true;
                }

                if (!vr.gpuSummary.empty()) vr.gpuSummary += " + ";
                vr.gpuSummary += name;
            }
            ad->Release();
        }
        f6->Release();
    }

    vr.isLaptop = chassisKnown ? chassisPortable : (hasBattery || hasMobileGpuName);

    if (vr.isLaptop) {
        if (hasIgpu && hasDgpu) {
            if (primaryOnDgpu) {
                vr.isMuxDirect = true;
                vr.topologySummary = TR("Laptop (MUX / dGPU Direct Active - Dual GPU)",
                                        "\xD0\x9D\xD0\xBE\xD1\x83\xD1\x82\xD0\xB1\xD1\x83\xD0\xBA (MUX / \xD0\xBF\xD1\x80\xD1\x8F\xD0\xBC\xD0\xBE\xD0\xB9 \xD0\xB2\xD1\x8B\xD0\xB2\xD0\xBE\xD0\xB4 \xD1\x81 dGPU \xE2\x80\x94 \xD0\xB4\xD0\xB2\xD0\xB0 GPU)");
            } else {
                vr.isHybridIgpuDisplay = true;
                vr.topologySummary = TR("Laptop (Hybrid Mode - Display via iGPU, Render on dGPU)",
                                        "\xD0\x9D\xD0\xBE\xD1\x83\xD1\x82\xD0\xB1\xD1\x83\xD0\xBA (\xD0\x93\xD0\xB8\xD0\xB1\xD1\x80\xD0\xB8\xD0\xB4\xD0\xBD\xD1\x8B\xD0\xB9 \xD1\x80\xD0\xB5\xD0\xB6\xD0\xB8\xD0\xBC \xE2\x80\x94 \xD0\xB2\xD1\x8B\xD0\xB2\xD0\xBE\xD0\xB4 \xD1\x87\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7 iGPU, \xD1\x80\xD0\xB5\xD0\xBD\xD0\xB4\xD0\xB5\xD1\x80 \xD0\xBD\xD0\xB0 dGPU)");
            }
        } else if (hasDgpu) {
            vr.isMuxDirect = true;
            vr.topologySummary = TR("Laptop (MUX / dGPU-Only Direct Mode)",
                                    "\xD0\x9D\xD0\xBE\xD1\x83\xD1\x82\xD0\xB1\xD1\x83\xD0\xBA (MUX / \xD1\x80\xD0\xB5\xD0\xB6\xD0\xB8\xD0\xBC \xD1\x82\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBA\xD0\xBE \xD0\xB4\xD0\xB8\xD1\x81\xD0\xBA\xD1\x80\xD0\xB5\xD1\x82\xD0\xBD\xD0\xBE\xD0\xB9 \xD0\xB2\xD0\xB8\xD0\xB4\xD0\xB5\xD0\xBE\xD0\xBA\xD0\xB0\xD1\x80\xD1\x82\xD1\x8B)");
        } else if (hasIgpu) {
            vr.topologySummary = TR("Laptop (Integrated GPU)",
                                    "\xD0\x9D\xD0\xBE\xD1\x83\xD1\x82\xD0\xB1\xD1\x83\xD0\xBA (\xD0\x92\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB5\xD0\xBD\xD0\xBD\xD0\xB0\xD1\x8F \xD0\xB3\xD1\x80\xD0\xB0\xD1\x84\xD0\xB8\xD0\xBA\xD0\xB0 iGPU)");
        } else {
            vr.topologySummary = TR("Laptop (Standard Display)",
                                    "\xD0\x9D\xD0\xBE\xD1\x83\xD1\x82\xD0\xB1\xD1\x83\xD0\xBA (\xD0\xA1\xD1\x82\xD0\xB0\xD0\xBD\xD0\xB4\xD0\xB0\xD1\x80\xD1\x82\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xB2\xD1\x8B\xD0\xB2\xD0\xBE\xD0\xB4)");
        }
    } else {
        if (hasDgpu && hasIgpu) {
            if (primaryOnIgpu && !primaryOnDgpu) {
                vr.isHybridIgpuDisplay = true;
                vr.topologySummary = TR("Desktop PC (Display via Motherboard iGPU - dGPU Offscreen)",
                                        "\xD0\x9D\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\x9F\xD0\x9A (\xD0\x9C\xD0\xBE\xD0\xBD\xD0\xB8\xD1\x82\xD0\xBE\xD1\x80 \xD0\xBF\xD0\xBE\xD0\xB4\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD1\x91\xD0\xBD \xD0\xBA iGPU \xE2\x80\x94 \xD1\x80\xD0\xB5\xD0\xBD\xD0\xB4\xD0\xB5\xD1\x80 \xD1\x81 dGPU)");
            } else {
                vr.isMuxDirect = true;
                vr.topologySummary = TR("Desktop PC (Discrete GPU Direct + iGPU Active)",
                                        "\xD0\x9D\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\x9F\xD0\x9A (\xD0\x94\xD0\xB8\xD1\x81\xD0\xBA\xD1\x80\xD0\xB5\xD1\x82\xD0\xBD\xD0\xB0\xD1\x8F \xD0\xB2\xD0\xB8\xD0\xB4\xD0\xB5\xD0\xBE\xD0\xBA\xD0\xB0\xD1\x80\xD1\x82\xD0\xB0 \xD0\xBD\xD0\xB0\xD0\xBF\xD1\x80\xD1\x8F\xD0\xBC\xD1\x83\xD1\x8E + iGPU \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xBD\xD0\xB0)");
            }
        } else if (hasDgpu) {
            vr.isMuxDirect = true;
            vr.topologySummary = TR("Desktop PC (Discrete GPU Direct)",
                                    "\xD0\x9D\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\x9F\xD0\x9A (\xD0\x94\xD0\xB8\xD1\x81\xD0\xBA\xD1\x80\xD0\xB5\xD1\x82\xD0\xBD\xD0\xB0\xD1\x8F \xD0\xB2\xD0\xB8\xD0\xB4\xD0\xB5\xD0\xBE\xD0\xBA\xD0\xB0\xD1\x80\xD1\x82\xD0\xB0 \xD0\xBD\xD0\xB0\xD0\xBF\xD1\x80\xD1\x8F\xD0\xBC\xD1\x83\xD1\x8E)");
        } else if (hasIgpu) {
            vr.topologySummary = TR("Desktop PC (Integrated GPU)",
                                    "\xD0\x9D\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\x9F\xD0\x9A (\xD0\x92\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB5\xD0\xBD\xD0\xBD\xD0\xB0\xD1\x8F \xD0\xB3\xD1\x80\xD0\xB0\xD1\x84\xD0\xB8\xD0\xBA\xD0\xB0 iGPU)");
        } else {
            vr.topologySummary = TR("Desktop PC (Standard Display)",
                                    "\xD0\x9D\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD0\xBB\xD1\x8C\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\x9F\xD0\x9A (\xD0\xA1\xD1\x82\xD0\xB0\xD0\xBD\xD0\xB4\xD0\xB0\xD1\x80\xD1\x82\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xB2\xD1\x8B\xD0\xB2\xD0\xBE\xD0\xB4)");
        }
    }
}

} // namespace

int DetectMaxMonitorHz() {
    int maxHz = 0, primHz = 0;
    DISPLAY_DEVICEW dd{};
    dd.cb = sizeof(dd);
    for (DWORD i = 0; EnumDisplayDevicesW(NULL, i, &dd, 0); ++i) {
        if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
        DEVMODEW dm{};
        dm.dmSize = sizeof(dm);
        if (EnumDisplaySettingsW(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm) && dm.dmDisplayFrequency >= 30) {
            int hz = static_cast<int>(dm.dmDisplayFrequency);
            if (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) primHz = hz;
            if (hz > maxHz) maxHz = hz;
        }
    }
    if (maxHz == 0) {
        DEVMODEW dm{}; dm.dmSize = sizeof(dm);
        if (EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dm)) maxHz = static_cast<int>(dm.dmDisplayFrequency);
    }
    return maxHz >= 30 ? maxHz : (primHz >= 30 ? primHz : 60);
}

int ComputeSafeTargetFps(const ModConfig& cfg, int monitorHz) {
    if (cfg.targetFpsOverride >= 30) return std::min(cfg.targetFpsOverride, 154);
    if (monitorHz >= 160) return 154;
    if (monitorHz >= 140) return 136;
    if (monitorHz >= 115) return 114;
    if (monitorHz >= 95)  return 95;
    if (monitorHz >= 70)  return monitorHz - 3;
    return 120;
}

bool EnsureExeGpuPreferences(const std::wstring& exePath) {
    if (exePath.empty()) return false;
    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\DirectX\\UserGpuPreferences",
                        0, NULL, 0, KEY_READ | KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS) {
        return false;
    }

    std::wstring cur;
    wchar_t buf[1024]{};
    DWORD sz = sizeof(buf) - sizeof(wchar_t);
    if (RegQueryValueExW(hk, exePath.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
        cur = buf;
    }
    std::wstring orig = cur;

    SetOrAddDxPref(cur, L"GpuPreference", L"2", false);
    SetOrAddDxPref(cur, L"SwapEffectUpgradeEnable", L"1", false);
    SetOrAddDxPref(cur, L"VRROptimizeEnable", L"1", false);

    bool ok = true;
    if (cur != orig) {
        ok = (RegSetValueExW(hk, exePath.c_str(), 0, REG_SZ,
                             reinterpret_cast<const BYTE*>(cur.c_str()),
                             static_cast<DWORD>((cur.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS);
    }
    RegCloseKey(hk);
    return ok;
}

VrrAuditResult RunVrrPreflight(const ModConfig& cfg, bool nonInteractive, const AuthProof& proof) {
    VrrAuditResult vr;
    if (!proof.isValid()) return vr;

    DetectDeviceTopology(vr);

    std::wstring winReg = ReadWinVrrReg();
    vr.winVrrRegEnabled = (winReg.find(L"VRROptimizeEnable=1") != std::wstring::npos);

    if (vr.hasAmdGpu) {
        CheckOrSetAdlxFreeSync(false, vr.adlxFreeSyncSupported, vr.adlxFreeSyncEnabled, vr.adlxChecked);
    }
    if (vr.hasNvidiaGpu) {
        CheckOrSetNvDrsGsync(0, vr.nvDrsChecked, vr.nvVrrMode);
        if (vr.isHybridIgpuDisplay && vr.nvDrsChecked && vr.nvVrrMode != 0) {
            CheckOrSetNvDrsGsync(2, vr.nvDrsChecked, vr.nvVrrMode);
        }
    }

    bool winOff = !vr.winVrrRegEnabled;
    bool amdOff = (vr.adlxFreeSyncSupported && !vr.adlxFreeSyncEnabled);
    bool nvOff  = (!vr.isHybridIgpuDisplay && vr.hasNvidiaGpu && vr.nvDrsChecked && vr.nvVrrMode == 0);
    vr.needsPrompt = (winOff || amdOff || nvOff);

    ConPrint(TR("  [2/5] System & GPU Topology : ", "  [2/5] \xD0\xA3\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB9\xD1\x81\xD1\x82\xD0\xB2\xD0\xBE \xD0\xB8 GPU      : ") +
             vr.topologySummary + "\n");
    ConPrint(TR("        -> Graphics Adapters  : ", "        -> \xD0\x92\xD0\xB8\xD0\xB4\xD0\xB5\xD0\xBE\xD0\xB0\xD0\xB4\xD0\xB0\xD0\xBF\xD1\x82\xD0\xB5\xD1\x80\xD1\x8B      : ") +
             (vr.gpuSummary.empty() ? TR("Standard Display", "\xD0\xA1\xD1\x82\xD0\xB0\xD0\xBD\xD0\xB4\xD0\xB0\xD1\x80\xD1\x82\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xB0\xD0\xB4\xD0\xB0\xD0\xBF\xD1\x82\xD0\xB5\xD1\x80") : vr.gpuSummary) + "\n");
    ConPrint(TR("        -> Windows VRR Opt    : ", "        -> Windows VRR        : ") +
             (vr.winVrrRegEnabled ? TR("ENABLED", "\xD0\x92\xD0\x9A\xD0\x9B") : TR("DISABLED", "\xD0\x92\xD0\xAB\xD0\x9A\xD0\x9B")) +
             TR(" | DXGI Tearing: ", " | DXGI Tearing: ") +
             (vr.dxgiAllowTearing ? TR("SUPPORTED", "\xD0\x9F\xD0\x9E\xD0\x94\xD0\x94\xD0\x95\xD0\xA0\xD0\x96\xD0\x98\xD0\x92\xD0\x90\xD0\x95\xD0\xA2\xD0\xA1\xD0\xAF") : TR("N/A", "\xD0\x9D\xD0\x95\xD0\xA2")) + "\n");
    if (vr.adlxChecked) {
        ConPrint(TR("        -> AMD FreeSync       : ", "        -> AMD FreeSync       : ") +
                 (vr.adlxFreeSyncSupported
                     ? (vr.adlxFreeSyncEnabled ? TR("ENABLED", "\xD0\x92\xD0\x9A\xD0\x9B") : TR("SUPPORTED (DISABLED)", "\xD0\x94\xD0\x9E\xD0\xA1\xD0\xA2\xD0\xA3\xD0\x9F\xD0\x95\xD0\x9D (\xD0\x92\xD0\xAB\xD0\x9A\xD0\x9B)"))
                     : TR("Not supported on panel", "\xD0\x9D\xD0\xB5 \xD0\xBF\xD0\xBE\xD0\xB4\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB6\xD0\xB8\xD0\xB2\xD0\xB0\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F \xD1\x8D\xD0\xBA\xD1\x80\xD0\xB0\xD0\xBD\xD0\xBE\xD0\xBC")) + "\n");
    }
    if (vr.nvDrsChecked) {
        std::string nvState = (vr.nvVrrMode == 2)
            ? TR("FULLSCREEN + WINDOWED", "\xD0\x9F\xD0\x9E\xD0\x9B\xD0\x9D\xD0\xAB\xD0\x99 \xD0\xAD\xD0\x9A\xD0\xA0\xD0\x90\xD0\x9D + \xD0\x9E\xD0\x9A\xD0\x9D\xD0\x9E")
            : ((vr.nvVrrMode == 1)
                ? TR("FULLSCREEN ONLY", "\xD0\xA2\xD0\x9E\xD0\x9B\xD0\xAC\xD0\x9A\xD0\x9E \xD0\x9F\xD0\x9E\xD0\x9B\xD0\x9D\xD0\xAB\xD0\x99 \xD0\xAD\xD0\x9A\xD0\xA0\xD0\x90\xD0\x9D")
                : TR("DEFAULT / OFF", "\xD0\x9F\xD0\x9E \xD0\xA3\xD0\x9C\xD0\x9E\xD0\x9B\xD0\xA7\xD0\x90\xD0\x9D\xD0\x98\xD0\xAE / \xD0\x92\xD0\xAB\xD0\x9A\xD0\x9B"));
        ConPrint(TR("        -> NVIDIA G-SYNC/VRR  : ", "        -> NVIDIA G-SYNC/VRR  : ") +
                 nvState + (vr.isHybridIgpuDisplay ? TR(" (Hybrid Mode Safe)", " (\xD0\x93\xD0\xB8\xD0\xB1\xD1\x80\xD0\xB8\xD0\xB4\xD0\xBD\xD1\x8B\xD0\xB9 \xD1\x80\xD0\xB5\xD0\xB6\xD0\xB8\xD0\xBC)") : "") + "\n");
    }

    if (vr.needsPrompt && cfg.autoVrr != "NO") {
        bool doEnable = (cfg.autoVrr == "YES");
        if (!doEnable && cfg.autoVrr == "ASK" && !nonInteractive) {
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("\n  [!] TIP: Best zero-tearing smoothness requires VRR / FreeSync / G-SYNC enabled.\n",
                        "\n  [!] \xD0\xA1\xD0\x9E\xD0\x92\xD0\x95\xD0\xA2: \xD0\x94\xD0\xBB\xD1\x8F \xD0\xB8\xD0\xB4\xD0\xB5\xD0\xB0\xD0\xBB\xD1\x8C\xD0\xBD\xD0\xBE\xD0\xB9 \xD0\xBF\xD0\xBB\xD0\xB0\xD0\xB2\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD0\xB8 \xD0\xB1\xD0\xB5\xD0\xB7 \xD1\x80\xD0\xB0\xD0\xB7\xD1\x80\xD1\x8B\xD0\xB2\xD0\xBE\xD0\xB2 \xD0\xB2\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD0\xB5 VRR / FreeSync / G-SYNC.\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            ConPrint(TR("  Enable recommended Windows/GPU VRR settings now? [Y/N]: ",
                        "  \xD0\x92\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD1\x8C \xD1\x80\xD0\xB5\xD0\xBA\xD0\xBE\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB4\xD1\x83\xD0\xB5\xD0\xBC\xD1\x8B\xD0\xB5 \xD0\xBD\xD0\xB0\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB9\xD0\xBA\xD0\xB8 VRR \xD1\x81\xD0\xB5\xD0\xB9\xD1\x87\xD0\xB0\xD1\x81? [Y (\xD0\x94\xD0\xB0) / N (\xD0\x9D\xD0\xB5\xD1\x82)]: "));
            std::string ans;
            if (std::getline(std::cin, ans)) {
                std::string u = ToUpperAscii(Trim(ans));
                if (!u.empty() && (u[0] == 'Y' || ans.find("\xD0\x94") != std::string::npos || ans.find("\xD0\xB4") != std::string::npos)) {
                    doEnable = true;
                }
            }
        }
        if (doEnable) {
            if (winOff) vr.winVrrRegEnabled = EnableWinVrrReg();
            if (amdOff) CheckOrSetAdlxFreeSync(true, vr.adlxFreeSyncSupported, vr.adlxFreeSyncEnabled, vr.adlxChecked);
            if (nvOff)  CheckOrSetNvDrsGsync(1, vr.nvDrsChecked, vr.nvVrrMode);
            SetColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("  [+] VRR / FreeSync / G-SYNC optimizations applied!\n",
                        "  [+] \xD0\x9D\xD0\xB0\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB9\xD0\xBA\xD0\xB8 VRR / FreeSync / G-SYNC \xD0\xBF\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB5\xD0\xBD\xD1\x8B!\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    return vr;
}

} // namespace cr1m
