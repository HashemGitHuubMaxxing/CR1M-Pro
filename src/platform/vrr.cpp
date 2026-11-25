// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/vrr.hpp"
#include "cr1m/hwid.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/util.hpp"
#include <dxgi1_6.h>
#include <shellapi.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

namespace cr1m {

namespace {

// Minimal ADLX C ABI interfaces verified against GPUOpen ADLX SDK
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
                    vr.primaryAdapterVendorId = d.VendorId;
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

void ParseCtaDataBlocks(const uint8_t* data, size_t len, EdidVrrCaps& out) {
    size_t pos = 0;
    while (pos < len) {
        uint8_t hdr = data[pos];
        uint8_t tag = static_cast<uint8_t>((hdr >> 5) & 0x07u);
        uint8_t blen = static_cast<uint8_t>(hdr & 0x1Fu);
        if (pos + 1u + blen > len) break;
        const uint8_t* p = data + pos + 1u;
        if (tag == 3u && blen >= 3u) {
            // AMD FreeSync Vendor Specific Data Block (IEEE OUI 00 00 1A)
            if (p[0] == 0x1Au && p[1] == 0x00u && p[2] == 0x00u && blen >= 7u) {
                out.hasFreeSyncVsdb = true;
                out.vrrSupported = true;
                uint16_t fMin = p[5];
                uint16_t fMax = p[6];
                if (fMin >= 20u && fMax > fMin && fMax <= 1000u) {
                    out.minHz = fMin;
                    out.maxHz = fMax;
                }
            }
            // HDMI 2.1 Forum Vendor Specific Data Block (IEEE OUI C4 5D D8)
            if (p[0] == 0xD8u && p[1] == 0x5Du && p[2] == 0xC4u && blen >= 9u) {
                uint16_t vMin = (blen >= 10u) ? static_cast<uint16_t>(p[9] & 0x3Fu) : 0u;
                uint16_t vMax = (blen >= 11u)
                    ? static_cast<uint16_t>(((static_cast<uint16_t>(p[9]) & 0xC0u) << 2) | p[10])
                    : 0u;
                bool cinemaOrCnm = ((p[8] & 0x50u) != 0);
                if ((vMin >= 20u && vMax > vMin && vMax <= 1000u) || vMin > 0u || cinemaOrCnm) {
                    out.hasHdmiVrr = true;
                    out.vrrSupported = true;
                    if (vMin >= 20u && vMax > vMin && vMax <= 1000u && out.maxHz == 0u) {
                        out.minHz = vMin;
                        out.maxHz = vMax;
                    }
                }
            }
        }
        pos += 1u + blen;
    }
}

bool QueryPrimaryDisplayEdidVrr(std::string& outDisplayName, EdidVrrCaps& outCaps) {
    outDisplayName.clear();
    outCaps = EdidVrrCaps{};

    UINT32 numPaths = 0, numModes = 0;
    if (GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &numPaths, &numModes) != ERROR_SUCCESS ||
        numPaths == 0 || numModes == 0 || numPaths > 128 || numModes > 256) {
        return false;
    }
    std::vector<DISPLAYCONFIG_PATH_INFO> paths(numPaths);
    std::vector<DISPLAYCONFIG_MODE_INFO> modes(numModes);
    if (QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &numPaths, paths.data(),
                           &numModes, modes.data(), nullptr) != ERROR_SUCCESS) {
        return false;
    }

    int primaryIdx = -1;
    for (UINT32 i = 0; i < numPaths; ++i) {
        UINT32 smIdx = paths[i].sourceInfo.modeInfoIdx;
        if (smIdx < numModes &&
            modes[smIdx].infoType == DISPLAYCONFIG_MODE_INFO_TYPE_SOURCE &&
            modes[smIdx].sourceMode.position.x == 0 &&
            modes[smIdx].sourceMode.position.y == 0) {
            primaryIdx = static_cast<int>(i);
            break;
        }
    }
    if (primaryIdx < 0) primaryIdx = 0;

    DISPLAYCONFIG_TARGET_DEVICE_NAME target{};
    target.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
    target.header.size = sizeof(target);
    target.header.adapterId = paths[static_cast<size_t>(primaryIdx)].targetInfo.adapterId;
    target.header.id = paths[static_cast<size_t>(primaryIdx)].targetInfo.id;
    if (DisplayConfigGetDeviceInfo(&target.header) != ERROR_SUCCESS) {
        return false;
    }

    if (target.monitorFriendlyDeviceName[0] != L'\0') {
        outDisplayName = WideToUtf8(target.monitorFriendlyDeviceName);
    }

    std::wstring devPath = target.monitorDevicePath;
    if (devPath.size() < 12) return false;
    if (devPath.rfind(L"\\\\?\\", 0) == 0) devPath = devPath.substr(4);

    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= devPath.size()) {
        size_t sep = devPath.find(L'#', start);
        if (sep == std::wstring::npos) {
            parts.push_back(devPath.substr(start));
            break;
        }
        parts.push_back(devPath.substr(start, sep - start));
        start = sep + 1;
    }
    if (parts.size() < 3 || parts[0].empty() || parts[1].empty() || parts[2].empty()) {
        return false;
    }
    for (size_t k = 0; k < 3; ++k) {
        if (parts[k].find(L'\\') != std::wstring::npos || parts[k].find(L"..") != std::wstring::npos) {
            return false;
        }
    }
    if (outDisplayName.empty()) {
        outDisplayName = WideToUtf8(parts[1]);
    }

    std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Enum\\" + parts[0] + L"\\" + parts[1] + L"\\" + parts[2] + L"\\Device Parameters";
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        return false;
    }
    DWORD valType = 0;
    DWORD cb = 0;
    std::vector<uint8_t> edid;
    if (RegQueryValueExW(hk, L"EDID", NULL, &valType, NULL, &cb) == ERROR_SUCCESS &&
        valType == REG_BINARY && cb >= 128 && cb <= 4096) {
        edid.resize(cb);
        if (RegQueryValueExW(hk, L"EDID", NULL, &valType, edid.data(), &cb) != ERROR_SUCCESS) {
            edid.clear();
        }
    }
    RegCloseKey(hk);
    if (edid.size() < 128) return false;

    auto tech = target.outputTechnology;
    bool digitalVrrLink =
        tech == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EXTERNAL ||
        tech == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EMBEDDED ||
        tech == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_UDI_EXTERNAL ||
        tech == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_UDI_EMBEDDED ||
        tech == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_HDMI ||
        tech == DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INTERNAL;

    outCaps = ParseEdidVrrCapabilities(std::span<const uint8_t>(edid.data(), edid.size()), digitalVrrLink);
    return outCaps.parsed;
}

bool TryLaunchFileOrShellW(const std::wstring& target) {
    if (target.empty()) return false;
    HINSTANCE r = ShellExecuteW(NULL, L"open", target.c_str(), NULL, NULL, SW_SHOWNORMAL);
    return reinterpret_cast<intptr_t>(r) > 32;
}

bool OpenGpuControlPanel(bool preferNvidia, bool preferAmd) {
    wchar_t pfBuf[MAX_PATH]{};
    DWORD pfLen = GetEnvironmentVariableW(L"ProgramFiles", pfBuf, static_cast<DWORD>(_countof(pfBuf)));
    std::wstring pf = (pfLen > 0 && pfLen < _countof(pfBuf)) ? std::wstring(pfBuf, pfLen) : L"C:\\Program Files";

    if (preferNvidia) {
        std::wstring nvApp = pf + L"\\NVIDIA Corporation\\NVIDIA App\\CEF\\NVIDIA App.exe";
        if (GetFileAttributesW(nvApp.c_str()) != INVALID_FILE_ATTRIBUTES && TryLaunchFileOrShellW(nvApp)) {
            return true;
        }
        if (TryLaunchFileOrShellW(L"shell:AppsFolder\\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj!NVIDIACorp.NVIDIAControlPanel")) {
            return true;
        }
    }
    if (preferAmd) {
        std::wstring amdApp = pf + L"\\AMD\\CNext\\CNext\\RadeonSoftware.exe";
        if (GetFileAttributesW(amdApp.c_str()) != INVALID_FILE_ATTRIBUTES && TryLaunchFileOrShellW(amdApp)) {
            return true;
        }
        if (TryLaunchFileOrShellW(L"shell:AppsFolder\\AdvancedMicroDevicesInc-2.AMDRadeonSoftware_0a9344xs7nr4m!AMDRadeonSoftware")) {
            return true;
        }
    }
    return TryLaunchFileOrShellW(L"ms-settings:display-advancedgraphics");
}

} // namespace

EdidVrrCaps ParseEdidVrrCapabilities(std::span<const uint8_t> edid, bool isDigitalVrrCapableLink) {
    EdidVrrCaps out{};
    if (edid.size() < 128u) return out;
    static constexpr uint8_t kEdidMagic[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    if (memcmp(edid.data(), kEdidMagic, sizeof(kEdidMagic)) != 0) return out;

    out.parsed = true;
    uint16_t rangeMin = 0, rangeMax = 0;
    bool continuousFreq = ((edid[24] & 0x01u) != 0);

    for (size_t descOff = 54u; descOff + 18u <= 126u; descOff += 18u) {
        const uint8_t* d = edid.data() + descOff;
        if (d[0] == 0x00u && d[1] == 0x00u && d[2] == 0x00u && d[3] == 0xFDu) {
            uint8_t flags = d[4];
            uint16_t minV = static_cast<uint16_t>(d[5]) + ((flags & 0x01u) ? 255u : 0u);
            uint16_t maxV = static_cast<uint16_t>(d[6]) + ((flags & 0x02u) ? 255u : 0u);
            if (minV >= 24u && maxV > minV && maxV <= 1000u && (maxV - minV) >= 15u) {
                rangeMin = minV;
                rangeMax = maxV;
                if (continuousFreq && isDigitalVrrCapableLink) {
                    out.hasContinuousRange = true;
                }
            }
        }
    }

    for (size_t blkOff = 128u; blkOff + 128u <= edid.size(); blkOff += 128u) {
        const uint8_t* blk = edid.data() + blkOff;
        if (blk[0] == 0x02u) {
            uint8_t dtdStart = blk[2];
            if (dtdStart > 4u && dtdStart <= 127u) {
                ParseCtaDataBlocks(blk + 4u, static_cast<size_t>(dtdStart - 4u), out);
            }
        } else if (blk[0] == 0x70u) {
            size_t secEnd = std::min<size_t>(5u + static_cast<size_t>(blk[2]), 126u);
            size_t pos = 5u;
            while (pos + 3u <= secEnd) {
                uint8_t tag = blk[pos];
                uint8_t dlen = blk[pos + 2u];
                if (tag == 0u && dlen == 0u) break;
                if (pos + 3u + dlen > secEnd) break;
                const uint8_t* p = blk + pos + 3u;
                if (tag == 0x81u && dlen >= 4u) {
                    // DisplayID 2.0 CTA container block embedding CTA 861 data blocks
                    ParseCtaDataBlocks(p, dlen, out);
                } else if (tag == 0x7Fu && dlen >= 7u) {
                    if (p[0] == 0x1Au && p[1] == 0x00u && p[2] == 0x00u) {
                        out.hasFreeSyncVsdb = true;
                        out.vrrSupported = true;
                        uint16_t fMin = p[5];
                        uint16_t fMax = p[6];
                        if (fMin >= 20u && fMax > fMin && fMax <= 1000u) {
                            out.minHz = fMin;
                            out.maxHz = fMax;
                        }
                    }
                } else if (tag == 0x25u && dlen >= 9u) {
                    uint16_t minV = p[6];
                    uint16_t maxV = static_cast<uint16_t>(p[7]) | (static_cast<uint16_t>(p[8] & 0x03u) << 8);
                    if (minV >= 20u && maxV > minV && maxV <= 1000u) {
                        out.hasContinuousRange = true;
                        if (out.maxHz == 0u) {
                            out.minHz = minV;
                            out.maxHz = maxV;
                        }
                    }
                }
                pos += 3u + dlen;
            }
        }
    }

    if (out.hasFreeSyncVsdb) {
        out.vrrSupported = true;
        out.sourceTag = "FreeSync";
    } else if (out.hasHdmiVrr) {
        out.vrrSupported = true;
        out.sourceTag = "HDMI VRR";
    } else if (out.hasContinuousRange) {
        out.vrrSupported = true;
        out.sourceTag = "Adaptive Sync";
    }
    if (out.minHz == 0u && rangeMin > 0u && rangeMax > rangeMin) {
        out.minHz = rangeMin;
        out.maxHz = rangeMax;
    }
    return out;
}

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
    vr.primaryVrrHardwareKnown = QueryPrimaryDisplayEdidVrr(vr.primaryDisplayName, vr.primaryEdidVrr);

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

    bool primaryIsAmd = (vr.primaryAdapterVendorId == 0x1002u) || (vr.isHybridIgpuDisplay && vr.hasAmdGpu);
    bool primaryIsNvidia = (!vr.isHybridIgpuDisplay && vr.hasNvidiaGpu &&
                            (vr.primaryAdapterVendorId == 0x10DEu || vr.primaryAdapterVendorId == 0u));

    vr.primaryVrrHardwareSupported = vr.primaryEdidVrr.vrrSupported ||
                                     (primaryIsAmd && vr.adlxChecked && vr.adlxFreeSyncSupported);
    if (!vr.primaryVrrHardwareKnown && primaryIsAmd && vr.adlxChecked) {
        vr.primaryVrrHardwareKnown = true;
    }

    bool vrrCapableOrUnknown = (!vr.primaryVrrHardwareKnown || vr.primaryVrrHardwareSupported);
    bool winOff = !vr.winVrrRegEnabled;
    bool amdOff = (primaryIsAmd && vr.adlxChecked && vr.adlxFreeSyncSupported && !vr.adlxFreeSyncEnabled);
    bool amdNeedManual = (primaryIsAmd && vr.primaryVrrHardwareSupported && !vr.adlxChecked);
    bool nvOff  = (primaryIsNvidia && vr.nvDrsChecked && vrrCapableOrUnknown && vr.nvVrrMode < 2u);
    vr.manualControlPanelNeeded = (amdNeedManual || nvOff);
    vr.needsPrompt = (winOff || amdOff || amdNeedManual || nvOff);

    ConPrint(TR("  [2/5] System & GPU Topology : ", "  [2/5] \xD0\xA3\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB9\xD1\x81\xD1\x82\xD0\xB2\xD0\xBE \xD0\xB8 GPU      : ") +
             vr.topologySummary + "\n");
    ConPrint(TR("        -> Graphics Adapters  : ", "        -> \xD0\x92\xD0\xB8\xD0\xB4\xD0\xB5\xD0\xBE\xD0\xB0\xD0\xB4\xD0\xB0\xD0\xBF\xD1\x82\xD0\xB5\xD1\x80\xD1\x8B      : ") +
             (vr.gpuSummary.empty() ? TR("Standard Display", "\xD0\xA1\xD1\x82\xD0\xB0\xD0\xBD\xD0\xB4\xD0\xB0\xD1\x80\xD1\x82\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xB0\xD0\xB4\xD0\xB0\xD0\xBF\xD1\x82\xD0\xB5\xD1\x80") : vr.gpuSummary) + "\n");
    if (vr.primaryVrrHardwareKnown) {
        std::string dispLabel = vr.primaryDisplayName.empty() ? std::string("Primary Panel") : vr.primaryDisplayName;
        if (vr.primaryVrrHardwareSupported) {
            std::string rangeStr;
            if (vr.primaryEdidVrr.minHz > 0 && vr.primaryEdidVrr.maxHz > vr.primaryEdidVrr.minHz) {
                rangeStr = std::to_string(vr.primaryEdidVrr.minHz) + " to " +
                           std::to_string(vr.primaryEdidVrr.maxHz) + " Hz";
            }
            std::string tag = vr.primaryEdidVrr.sourceTag.empty() ? std::string("VRR") : vr.primaryEdidVrr.sourceTag;
            ConPrint(TR("        -> Display VRR Cap    : ", "        -> \xD0\xAD\xD0\xBA\xD1\x80\xD0\xB0\xD0\xBD VRR          : ") +
                     dispLabel + " (" + TR("Supported", "\xD0\x9F\xD0\xBE\xD0\xB4\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB6\xD0\xB8\xD0\xB2\xD0\xB0\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F") +
                     (rangeStr.empty() ? "" : ": " + rangeStr) + " via " + tag + ")\n");
        } else {
            ConPrint(TR("        -> Display VRR Cap    : ", "        -> \xD0\xAD\xD0\xBA\xD1\x80\xD0\xB0\xD0\xBD VRR          : ") +
                     dispLabel + TR(" (Fixed Refresh Panel; VRR Not Supported)\n",
                                    " (\xD0\xA4\xD0\xB8\xD0\xBA\xD1\x81. \xD1\x87\xD0\xB0\xD1\x81\xD1\x82\xD0\xBE\xD1\x82\xD0\xB0; VRR \xD0\xBD\xD0\xB5 \xD0\xBF\xD0\xBE\xD0\xB4\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB6\xD0\xB8\xD0\xB2\xD0\xB0\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F)\n"));
        }
    }
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
        bool openApp = false;
        if (!doEnable && cfg.autoVrr == "ASK" && !nonInteractive) {
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            ConPrint(TR("\n  [!] TIP: Your primary display supports VRR. Enable VRR / FreeSync / G-SYNC for maximum smoothness.\n",
                        "\n  [!] \xD0\xA1\xD0\x9E\xD0\x92\xD0\x95\xD0\xA2: \xD0\x92\xD0\xB0\xD1\x88 \xD1\x8D\xD0\xBA\xD1\x80\xD0\xB0\xD0\xBD \xD0\xBF\xD0\xBE\xD0\xB4\xD0\xB4\xD0\xB5\xD1\x80\xD0\xB6\xD0\xB8\xD0\xB2\xD0\xB0\xD0\xB5\xD1\x82 VRR. \xD0\x92\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD0\xB5 VRR / FreeSync / G-SYNC.\n"));
            if (nvOff) {
                ConPrint(TR("      NVIDIA App: System -> Displays -> G-SYNC (Enable for Windowed and Fullscreen)\n",
                            "      NVIDIA App: \xD0\xA1\xD0\xB8\xD1\x81\xD1\x82\xD0\xB5\xD0\xBC\xD0\xB0 -> \xD0\x94\xD0\xB8\xD1\x81\xD0\xBF\xD0\xBB\xD0\xB5\xD0\xB8 -> G-SYNC (\xD0\xB4\xD0\xBB\xD1\x8F \xD0\xBE\xD0\xBA\xD0\xBD\xD0\xB0 \xD0\xB8 \xD0\xBF\xD0\xBE\xD0\xBB\xD0\xBD\xD0\xBE\xD0\xB3\xD0\xBE \xD1\x8D\xD0\xBA\xD1\x80\xD0\xB0\xD0\xBD\xD0\xB0)\n"));
            } else if (amdOff || amdNeedManual) {
                ConPrint(TR("      AMD Adrenalin: Gaming -> Display -> AMD FreeSync (Enabled)\n",
                            "      AMD Adrenalin: \xD0\x98\xD0\xB3\xD1\x80\xD1\x8B -> \xD0\x94\xD0\xB8\xD1\x81\xD0\xBF\xD0\xBB\xD0\xB5\xD0\xB9 -> AMD FreeSync (\xD0\x92\xD0\xBA\xD0\xBB)\n"));
            }
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            ConPrint(TR("  Enable recommended VRR settings now? [Y = Auto Enable / O = Open GPU App / N = Skip]: ",
                        "  \xD0\x92\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD1\x8C VRR \xD1\x81\xD0\xB5\xD0\xB9\xD1\x87\xD0\xB0\xD1\x81? [Y = \xD0\x92\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD1\x8C / O = \xD0\x9E\xD1\x82\xD0\xBA\xD1\x80\xD1\x8B\xD1\x82\xD1\x8C GPU App / N = \xD0\x9F\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x81\xD1\x82\xD0\xB8\xD1\x82\xD1\x8C]: "));
            std::string ans;
            if (std::getline(std::cin, ans)) {
                std::string t = Trim(ans);
                std::string u = ToUpperAscii(t);
                if (!u.empty() && (u[0] == 'Y' || t.find("\xD0\x94") == 0 || t.find("\xD0\xB4") == 0)) {
                    doEnable = true;
                } else if (!u.empty() && (u[0] == 'O' || t.find("\xD0\x9E") == 0 || t.find("\xD0\xBE") == 0)) {
                    openApp = true;
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
            if ((nvOff && vr.nvVrrMode < 2u) || (amdOff && !vr.adlxFreeSyncEnabled) || amdNeedManual) {
                SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                ConPrint(TR("  [!] Note: Confirm per display G-SYNC / FreeSync is enabled in your GPU app if not yet active.\n",
                            "  [!] \xD0\x9F\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD1\x87\xD0\xB0\xD0\xBD\xD0\xB8\xD0\xB5: \xD0\xBF\xD1\x80\xD0\xBE\xD0\xB2\xD0\xB5\xD1\x80\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xBF\xD0\xB5\xD1\x80\xD0\xB5\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB0\xD1\x82\xD0\xB5\xD0\xBB\xD1\x8C G-SYNC / FreeSync \xD0\xB2 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xBB\xD0\xBE\xD0\xB6\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB8 GPU.\n"));
            }
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        } else if (openApp) {
            OpenGpuControlPanel(primaryIsNvidia, primaryIsAmd);
            SetColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            ConPrint(TR("  [+] Opened GPU display settings. Enable VRR / G-SYNC / FreeSync, then continue launching.\n",
                        "  [+] \xD0\x9E\xD1\x82\xD0\xBA\xD1\x80\xD1\x8B\xD1\x82\xD1\x8B \xD0\xBD\xD0\xB0\xD1\x81\xD1\x82\xD1\x80\xD0\xBE\xD0\xB9\xD0\xBA\xD0\xB8 \xD0\xB4\xD0\xB8\xD1\x81\xD0\xBF\xD0\xBB\xD0\xB5\xD1\x8F GPU. \xD0\x92\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD0\xB5 VRR / G-SYNC / FreeSync.\n"));
            SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    return vr;
}

} // namespace cr1m
