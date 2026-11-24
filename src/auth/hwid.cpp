// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/hwid.hpp"
#include "cr1m/auth.hpp"
#include "cr1m/i18n.hpp"
#include "cr1m/util.hpp"
#include <cpuid.h>
#include <dxgi1_6.h>
#include <winioctl.h>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace cr1m {

namespace {

#pragma pack(push, 1)
struct HwBaselinePayload {
    uint32_t magic;
    uint32_t version;
    BYTE     cpuSha[32];
    BYTE     gpuSha[32];
    BYTE     boardSha[32];
    BYTE     diskSha[32];
    BYTE     v1Sha[32];
    uint8_t  hasDisk;
    uint8_t  reserved[7];
};
struct HwBaselineDiskBlob {
    uint32_t hdrMagic;
    BYTE     nonce[8];
    uint8_t  cipher[sizeof(HwBaselinePayload)];
    BYTE     mac[16];
};
#pragma pack(pop)

constexpr uint32_t HW_BASE_MAGIC     = 0x42574843u; // "CHWB"
constexpr uint32_t HW_BASE_HDR_MAGIC = 0x31424843u; // "CHB1"

std::string FormatCr1mHwidFromHash(const BYTE hash[32]) {
    std::string h = BytesToUpperHex(hash, 6);
    return "CR1M-" + h.substr(0, 4) + "-" + h.substr(4, 4) + "-" + h.substr(8, 4);
}

std::string ExtractSmbiosString(const std::vector<uint8_t>& buf, size_t strTableStart, uint8_t oneBasedIdx) {
    if (oneBasedIdx == 0) return "";
    size_t pos = strTableStart;
    uint8_t curIdx = 1;
    while (pos < buf.size() && buf[pos] != 0) {
        size_t end = pos;
        while (end < buf.size() && buf[end] != 0) ++end;
        if (curIdx == oneBasedIdx) {
            std::string raw(reinterpret_cast<const char*>(&buf[pos]), end - pos);
            return Trim(raw);
        }
        pos = end + 1;
        ++curIdx;
    }
    return "";
}

bool IsKnownIgpuVendorDesc(UINT vendorId, uint64_t vramMb, const std::string& upperName) {
    if (vendorId == 0x10DE) return false;
    if (vendorId == 0x8086) {
        if (upperName.find("130V") != std::string::npos || upperName.find("140V") != std::string::npos ||
            upperName.find("130T") != std::string::npos || upperName.find("140T") != std::string::npos) {
            return true;
        }
        return !(upperName.find("ARC") != std::string::npos && vramMb > 2048);
    }
    if (vendorId == 0x1002) {
        if (upperName.find("RX ") != std::string::npos || upperName.find("PRO ") != std::string::npos) return false;
        if (vramMb <= 2048) return true;
        if (upperName.find("840M") != std::string::npos || upperName.find("860M") != std::string::npos ||
            upperName.find("8040S") != std::string::npos || upperName.find("8050S") != std::string::npos ||
            upperName.find("8060S") != std::string::npos || upperName.find("RADEON(TM) 7") != std::string::npos ||
            upperName.find("RADEON(TM) 8") != std::string::npos || upperName.find("RADEON GRAPHICS") != std::string::npos) {
            return true;
        }
        if (upperName.find("610M") != std::string::npos || upperName.find("660M") != std::string::npos ||
            upperName.find("680M") != std::string::npos || upperName.find("740M") != std::string::npos ||
            upperName.find("760M") != std::string::npos || upperName.find("780M") != std::string::npos ||
            upperName.find("880M") != std::string::npos || upperName.find("890M") != std::string::npos ||
            upperName.find("GRAPHICS") != std::string::npos || upperName.find("VEGA") != std::string::npos) {
            return true;
        }
        return false;
    }
    return vramMb <= 1024;
}

std::string ReadGpuHardwareSig() {
    std::string bestDiscreteSig;
    uint64_t bestDiscreteVram = 0;
    std::string bestFallbackSig;
    uint64_t bestFallbackVram = 0;

    IDXGIFactory1* f1 = nullptr;
    if (SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&f1))) && f1) {
        for (UINT i = 0; ; ++i) {
            IDXGIAdapter1* ad = nullptr;
            if (f1->EnumAdapters1(i, &ad) == DXGI_ERROR_NOT_FOUND) break;
            DXGI_ADAPTER_DESC1 d{};
            if (SUCCEEDED(ad->GetDesc1(&d)) && d.VendorId != 0x1414 && !(d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                uint64_t vramMb = static_cast<uint64_t>(d.DedicatedVideoMemory / (1024ULL * 1024ULL));
                std::string up = ToUpperAscii(WideToUtf8(d.Description));
                bool isIgpu = IsKnownIgpuVendorDesc(d.VendorId, vramMb, up);
                std::ostringstream gs;
                gs << std::hex << std::uppercase << std::setfill('0')
                   << std::setw(4) << d.VendorId << ":"
                   << std::setw(4) << d.DeviceId << ":"
                   << std::setw(8) << d.SubSysId << ":"
                   << std::setw(2) << d.Revision;
                std::string s = gs.str();
                if (!isIgpu && (bestDiscreteSig.empty() || vramMb > bestDiscreteVram ||
                                (vramMb == bestDiscreteVram && s < bestDiscreteSig))) {
                    bestDiscreteVram = vramMb;
                    bestDiscreteSig = s;
                }
                uint64_t fbScore = ((d.VendorId == 0x10DE || d.VendorId == 0x1002 || d.VendorId == 0x8086)
                                        ? (1ULL << 40) : 0ULL) + vramMb;
                if (bestFallbackSig.empty() || fbScore > bestFallbackVram ||
                    (fbScore == bestFallbackVram && s < bestFallbackSig)) {
                    bestFallbackVram = fbScore;
                    bestFallbackSig = s;
                }
            }
            ad->Release();
        }
        f1->Release();
    }
    if (!bestDiscreteSig.empty()) return bestDiscreteSig;
    if (!bestFallbackSig.empty()) return bestFallbackSig;
    return "NO_DXGI_GPU";
}

void ReadCpuHardware(std::string& outCpuSig, bool& outUnexpectedHv, std::string& outHvVendor) {
    outUnexpectedHv = false;
    outHvVendor.clear();
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    char vendor[13]{};
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        memcpy(vendor + 0, &ebx, 4);
        memcpy(vendor + 4, &edx, 4);
        memcpy(vendor + 8, &ecx, 4);
    }

    unsigned int fms = 0;
    bool hvPresent = false;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        fms = (eax & 0x0FFFFFFFu);
        hvPresent = ((ecx >> 31) & 1u) != 0;
    }

    char brand[49]{};
    unsigned int maxExt = 0;
    __cpuid_count(0x80000000u, 0, maxExt, ebx, ecx, edx);
    if (maxExt >= 0x80000004u) {
        for (unsigned int k = 0; k < 3; ++k) {
            unsigned int a2 = 0, b2 = 0, c2 = 0, d2 = 0;
            __cpuid_count(0x80000002u + k, 0, a2, b2, c2, d2);
            memcpy(brand + k * 16 + 0,  &a2, 4);
            memcpy(brand + k * 16 + 4,  &b2, 4);
            memcpy(brand + k * 16 + 8,  &c2, 4);
            memcpy(brand + k * 16 + 12, &d2, 4);
        }
    }

    if (hvPresent) {
        unsigned int hMax = 0, hb = 0, hc = 0, hd = 0;
        __cpuid_count(0x40000000u, 0, hMax, hb, hc, hd);
        char hv[13]{};
        memcpy(hv + 0, &hb, 4);
        memcpy(hv + 4, &hc, 4);
        memcpy(hv + 8, &hd, 4);
        outHvVendor = Trim(std::string(hv, 12));
        if (!outHvVendor.empty() && outHvVendor != "Microsoft Hv") {
            outUnexpectedHv = true;
        }
    }

    std::ostringstream cs;
    cs << Trim(vendor) << "|" << std::hex << std::uppercase << fms << "|" << ToUpperAscii(Trim(brand));
    outCpuSig = cs.str();
}

bool IsDummyHardwareSerial(const std::string& s) {
    std::string u = ToUpperAscii(Trim(s));
    if (u.empty()) return false;
    std::string stripped;
    for (char c : u) {
        if (std::isalnum(static_cast<unsigned char>(c))) stripped.push_back(c);
    }
    if (stripped.size() < 4) return true;
    bool allSame = true;
    for (size_t i = 1; i < stripped.size(); ++i) {
        if (stripped[i] != stripped[0]) { allSame = false; break; }
    }
    if (allSame) return true;
    if (stripped == "123456" || stripped == "12345678" ||
        stripped == "123456789" || stripped == "0123456789" ||
        stripped == "DEFAULT" || stripped == "DEFAULTSTRING" ||
        stripped == "TOBEFILLEDBYOEM" || stripped == "NONE") {
        return true;
    }
    return false;
}

void ReadPhysicalDiskInfo(bool& outAvail, std::string& outDiskSig, bool& outDummySerial) {
    outAvail = false;
    outDiskSig.clear();
    outDummySerial = false;

    HANDLE hVol = CreateFileW(L"\\\\.\\C:", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return;

    STORAGE_DEVICE_NUMBER sdn{};
    DWORD bytesRet = 0;
    bool gotDev = (DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(sdn), &bytesRet, NULL) != FALSE);
    CloseHandle(hVol);
    if (!gotDev) return;

    std::wstring drvPath = L"\\\\.\\PhysicalDrive" + std::to_wstring(sdn.DeviceNumber);
    HANDLE hDisk = CreateFileW(drvPath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk == INVALID_HANDLE_VALUE) return;

    STORAGE_PROPERTY_QUERY spq{};
    spq.PropertyId = StorageDeviceProperty;
    spq.QueryType  = PropertyStandardQuery;
    uint8_t buf[1024]{};
    if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &spq, sizeof(spq), buf, sizeof(buf), &bytesRet, NULL) &&
        bytesRet >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        const auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf);
        auto readOffStr = [&](DWORD off) -> std::string {
            if (off == 0 || off >= bytesRet) return "";
            const char* p = reinterpret_cast<const char*>(buf + off);
            size_t maxLen = bytesRet - off;
            size_t n = 0;
            while (n < maxLen && p[n] != '\0') ++n;
            return Trim(std::string(p, n));
        };
        std::string v = readOffStr(desc->VendorIdOffset);
        std::string p = readOffStr(desc->ProductIdOffset);
        std::string s = readOffStr(desc->SerialNumberOffset);
        if (!p.empty() || !s.empty()) {
            outAvail = true;
            outDiskSig = ToUpperAscii(v + "|" + p + "|" + s);
            if (!s.empty() && IsDummyHardwareSerial(s)) {
                outDummySerial = true;
            }
        }
    }
    CloseHandle(hDisk);
}

std::string ReadRegBiosValue(const std::wstring& valName) {
    HKEY hKey = NULL;
    std::string res;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        WCHAR buf[256]{};
        DWORD cb = sizeof(buf) - sizeof(WCHAR);
        if (RegQueryValueExW(hKey, valName.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(buf), &cb) == ERROR_SUCCESS) {
            res = Trim(WideToUtf8(buf));
        }
        RegCloseKey(hKey);
    }
    return res;
}

bool SealOrOpenBaselineBlob(bool isSeal, const BYTE sealKey[32], HwBaselinePayload& ioPl, HwBaselineDiskBlob& ioBlob) {
    BCRYPT_ALG_HANDLE hSha = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        return false;
    }

    if (isSeal) {
        ioBlob.hdrMagic = HW_BASE_HDR_MAGIC;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, ioBlob.nonce, sizeof(ioBlob.nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            uint64_t tc = GetTickCount64() ^ __rdtsc();
            memcpy(ioBlob.nonce, &tc, 8);
        }
    } else {
        if (ioBlob.hdrMagic != HW_BASE_HDR_MAGIC) {
            BCryptCloseAlgorithmProvider(hSha, 0);
            return false;
        }
        uint8_t macIn[32 + 8 + sizeof(HwBaselinePayload)]{};
        memcpy(macIn, sealKey, 32);
        memcpy(macIn + 32, ioBlob.nonce, 8);
        memcpy(macIn + 40, ioBlob.cipher, sizeof(HwBaselinePayload));
        BYTE macFull[32]{};
        ComputeSha256(hSha, macIn, sizeof(macIn), macFull);
        uint8_t diff = 0;
        for (int i = 0; i < 16; ++i) diff |= (macFull[i] ^ ioBlob.mac[i]);
        SecureZeroMemory(macIn, sizeof(macIn));
        SecureZeroMemory(macFull, sizeof(macFull));
        if (diff != 0) {
            BCryptCloseAlgorithmProvider(hSha, 0);
            return false;
        }
    }

    BYTE streamIn[40]{};
    memcpy(streamIn, sealKey, 32);
    memcpy(streamIn + 32, ioBlob.nonce, 8);
    BYTE blocks[6][32]{};
    for (int b = 0; b < 6; ++b) {
        streamIn[32] ^= static_cast<uint8_t>(0x33u + b * 17u);
        ComputeSha256(hSha, streamIn, sizeof(streamIn), blocks[b]);
    }
    SecureZeroMemory(streamIn, sizeof(streamIn));

    uint8_t* plPtr = reinterpret_cast<uint8_t*>(&ioPl);
    for (size_t i = 0; i < sizeof(HwBaselinePayload); ++i) {
        uint8_t kb = blocks[i / 32][i % 32];
        if (isSeal) ioBlob.cipher[i] = plPtr[i] ^ kb;
        else        plPtr[i] = ioBlob.cipher[i] ^ kb;
    }
    SecureZeroMemory(blocks, sizeof(blocks));

    if (isSeal) {
        uint8_t macIn[32 + 8 + sizeof(HwBaselinePayload)]{};
        memcpy(macIn, sealKey, 32);
        memcpy(macIn + 32, ioBlob.nonce, 8);
        memcpy(macIn + 40, ioBlob.cipher, sizeof(HwBaselinePayload));
        BYTE macFull[32]{};
        ComputeSha256(hSha, macIn, sizeof(macIn), macFull);
        memcpy(ioBlob.mac, macFull, 16);
        SecureZeroMemory(macIn, sizeof(macIn));
        SecureZeroMemory(macFull, sizeof(macFull));
    }

    BCryptCloseAlgorithmProvider(hSha, 0);
    return isSeal ? true : (ioPl.magic == HW_BASE_MAGIC && ioPl.version == 1);
}

} // namespace

bool SpoofReport::hasTrialBlockFlag() const {
    return regVsSmbiosMismatch || boardBaselineDrift;
}

bool SpoofReport::hasPurchaseWarning() const {
    return regVsSmbiosMismatch || badSmbiosUuid || unexpectedHypervisor ||
           boardBaselineDrift || dummyDiskSerial || diskBaselineDrift;
}

std::string SpoofReport::summaryEn() const {
    std::vector<std::string> r;
    if (regVsSmbiosMismatch) r.push_back("Registry BIOS vs Raw SMBIOS mismatch");
    if (badSmbiosUuid)       r.push_back("Invalid/Zeroed/Synthetic SMBIOS System UUID");
    if (unexpectedHypervisor) r.push_back("Non-Windows Hypervisor/VM active (" + hvVendor + ")");
    if (dummyDiskSerial)     r.push_back("Anomalous dummy disk serial");
    if (boardBaselineDrift)  r.push_back("Motherboard/SMBIOS changed since PC baseline");
    if (diskBaselineDrift)   r.push_back("Physical drive serial changed since PC baseline");
    std::string out;
    for (size_t i = 0; i < r.size(); ++i) {
        if (i) out += "; ";
        out += r[i];
    }
    return out;
}

std::string SpoofReport::summaryRu() const {
    std::vector<std::string> r;
    if (regVsSmbiosMismatch) r.push_back("\xD0\xA0\xD0\xB0\xD1\x81\xD1\x85\xD0\xBE\xD0\xB6\xD0\xB4\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xB5 \xD1\x80\xD0\xB5\xD0\xB5\xD1\x81\xD1\x82\xD1\x80\xD0\xB0 BIOS \xD0\xB8 SMBIOS");
    if (badSmbiosUuid)       r.push_back("\xD0\x9D\xD0\xB5\xD0\xBA\xD0\xBE\xD1\x80\xD1\x80\xD0\xB5\xD0\xBA\xD1\x82\xD0\xBD\xD1\x8B\xD0\xB9/\xD1\x84\xD0\xB8\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xBD\xD1\x8B\xD0\xB9 SMBIOS UUID");
    if (unexpectedHypervisor) r.push_back("\xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB5\xD0\xBD \xD1\x81\xD1\x82\xD0\xBE\xD1\x80\xD0\xBE\xD0\xBD\xD0\xBD\xD0\xB8\xD0\xB9 \xD0\xB3\xD0\xB8\xD0\xBF\xD0\xB5\xD1\x80\xD0\xB2\xD0\xB8\xD0\xB7\xD0\xBE\xD1\x80/VM (" + hvVendor + ")");
    if (dummyDiskSerial)     r.push_back("\xD0\xA4\xD0\xB8\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xBD\xD1\x8B\xD0\xB9 \xD1\x81\xD0\xB5\xD1\x80\xD0\xB8\xD0\xB9\xD0\xBD\xD1\x8B\xD0\xB9 \xD0\xBD\xD0\xBE\xD0\xBC\xD0\xB5\xD1\x80 \xD0\xB4\xD0\xB8\xD1\x81\xD0\xBA\xD0\xB0");
    if (boardBaselineDrift)  r.push_back("SMBIOS/\xD0\x9F\xD0\xBB\xD0\xB0\xD1\x82\xD0\xB0 \xD0\xB8\xD0\xB7\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xBB\xD0\xB8\xD1\x81\xD1\x8C \xD0\xBE\xD1\x82\xD0\xBD\xD0\xBE\xD1\x81\xD0\xB8\xD1\x82\xD0\xB5\xD0\xBB\xD1\x8C\xD0\xBD\xD0\xBE \xD0\xB1\xD0\xB0\xD0\xB7\xD1\x8B \xD0\x9F\xD0\x9A");
    if (diskBaselineDrift)   r.push_back("\xD0\xA1\xD0\xB5\xD1\x80\xD0\xB8\xD0\xB9\xD0\xBD\xD0\xB8\xD0\xBA \xD0\xB4\xD0\xB8\xD1\x81\xD0\xBA\xD0\xB0 \xD0\xB8\xD0\xB7\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB8\xD0\xBB\xD1\x81\xD1\x8F \xD0\xBE\xD1\x82\xD0\xBD\xD0\xBE\xD1\x81\xD0\xB8\xD1\x82\xD0\xB5\xD0\xBB\xD1\x8C\xD0\xBD\xD0\xBE \xD0\xB1\xD0\xB0\xD0\xB7\xD1\x8B \xD0\x9F\xD0\x9A");
    std::string out;
    for (size_t i = 0; i < r.size(); ++i) {
        if (i) out += "; ";
        out += r[i];
    }
    return out;
}

SmbiosSnapshot ReadSmbiosSnapshot() {
    SmbiosSnapshot snap;
    DWORD sz = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (sz < 16 || sz > 1024 * 1024) return snap;
    std::vector<uint8_t> buf(sz);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), sz) != sz) return snap;

    size_t i = 8;
    while (i + 4 <= buf.size()) {
        uint8_t type = buf[i];
        uint8_t len = buf[i + 1];
        if (len < 4 || i + len > buf.size()) break;
        size_t strStart = i + len;

        if (type == 1 && len >= 8) {
            snap.sysMfr    = ExtractSmbiosString(buf, strStart, buf[i + 4]);
            snap.sysProd   = ExtractSmbiosString(buf, strStart, buf[i + 5]);
            snap.sysSerial = ExtractSmbiosString(buf, strStart, buf[i + 7]);
            if (len >= 24 && i + 24 <= buf.size()) {
                bool z = true, ff = true;
                int sameCount = 0;
                uint8_t firstB = buf[i + 8];
                for (int k = 0; k < 16; ++k) {
                    uint8_t b = buf[i + 8 + k];
                    if (b != 0x00) z = false;
                    if (b != 0xFF) ff = false;
                    if (b == firstB) ++sameCount;
                }
                snap.uuidAllZero   = z;
                snap.uuidAllFF     = ff;
                snap.uuidMalformed = (!z && !ff && sameCount >= 14);
                snap.uuidHex       = BytesToUpperHex(&buf[i + 8], 16);
            }
        } else if (type == 2 && len >= 8) {
            snap.boardMfr    = ExtractSmbiosString(buf, strStart, buf[i + 4]);
            snap.boardProd   = ExtractSmbiosString(buf, strStart, buf[i + 5]);
            snap.boardSerial = ExtractSmbiosString(buf, strStart, buf[i + 7]);
        } else if (type == 3 && len >= 6 && snap.chassisType < 0) {
            snap.chassisType = static_cast<int>(buf[i + 5] & 0x7F);
        }

        size_t j = strStart;
        while (j + 1 < buf.size() && !(buf[j] == 0 && buf[j + 1] == 0)) ++j;
        i = j + 2;
        if (type == 127) break;
    }
    return snap;
}

HwidBundle ComputeHwidBundle() {
    HwidBundle hb;

    // 1. Legacy V1 HWID (preserved for legacy trial anchor decryption)
    std::string guid;
    {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            WCHAR buf[256]{};
            DWORD cb = sizeof(buf) - sizeof(WCHAR);
            if (RegQueryValueExW(hKey, L"MachineGuid", NULL, NULL, reinterpret_cast<LPBYTE>(buf), &cb) == ERROR_SUCCESS) {
                guid = WideToUtf8(buf);
            }
            RegCloseKey(hKey);
        }
    }
    DWORD serial = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    {
        std::stringstream ss;
        ss << "CR1M_SALT_v1|" << guid << "|" << std::hex << std::uppercase << serial
           << "|" << std::dec << si.dwNumberOfProcessors;
        std::string raw = ss.str();
        BYTE h1[32]{};
        ComputeSha256Bytes(raw.data(), raw.size(), h1);
        WipeStr(raw);
        hb.v1 = FormatCr1mHwidFromHash(h1);
        SecureZeroMemory(h1, sizeof(h1));
    }

    // 2. Physical Silicon Hardware Profile (V2 HWID + Trial Phys Anchor + Spoofer Audit)
    std::string cpuSig, hvVendor;
    bool unexpHv = false;
    ReadCpuHardware(cpuSig, unexpHv, hvVendor);
    hb.spoof.unexpectedHypervisor = unexpHv;
    hb.spoof.hvVendor = hvVendor;

    SmbiosSnapshot smbios = ReadSmbiosSnapshot();
    if (smbios.uuidAllZero || smbios.uuidAllFF || smbios.uuidMalformed) {
        hb.spoof.badSmbiosUuid = true;
    }

    auto diffNonEmpty = [](const std::string& a, const std::string& b) -> bool {
        if (a.empty() || b.empty()) return false;
        return ToUpperAscii(Trim(a)) != ToUpperAscii(Trim(b));
    };
    std::string regSysProd   = ReadRegBiosValue(L"SystemProductName");
    std::string regBoardProd = ReadRegBiosValue(L"BaseBoardProduct");
    std::string regBoardMfr  = ReadRegBiosValue(L"BaseBoardManufacturer");
    if (diffNonEmpty(regSysProd, smbios.sysProd) ||
        diffNonEmpty(regBoardProd, smbios.boardProd) ||
        diffNonEmpty(regBoardMfr, smbios.boardMfr)) {
        hb.spoof.regVsSmbiosMismatch = true;
    }

    std::string gpuSig = ReadGpuHardwareSig();

    bool diskAvail = false, dummyDisk = false;
    std::string diskSig;
    ReadPhysicalDiskInfo(diskAvail, diskSig, dummyDisk);
    hb.spoof.dummyDiskSerial = dummyDisk;

    // Exclude volatile BIOS version so motherboard BIOS updates never break V2 keys
    std::string boardSig = ToUpperAscii(
        smbios.uuidHex + "|" + smbios.sysMfr + "|" + smbios.sysProd + "|" +
        smbios.boardMfr + "|" + smbios.boardProd + "|" + smbios.boardSerial
    );

    {
        std::string v2In = "CR1M_HWID_V2|" + cpuSig + "|" + boardSig + "|" + gpuSig;
        BYTE h2[32]{};
        ComputeSha256Bytes(v2In.data(), v2In.size(), h2);
        WipeStr(v2In);
        hb.v2 = FormatCr1mHwidFromHash(h2);
        SecureZeroMemory(h2, sizeof(h2));
    }

    {
        std::string ptIn = "CR1M_TRIAL_PHYS_V1|" + cpuSig + "|" + boardSig + "|" + gpuSig;
        BYTE ht[32]{};
        ComputeSha256Bytes(ptIn.data(), ptIn.size(), ht);
        WipeStr(ptIn);
        hb.physTrialId = BytesToUpperHex(ht, 32);
        SecureZeroMemory(ht, sizeof(ht));
    }

    // 3. Sealed Local Hardware Baseline Drift Check (keyed to immutable CPU + GPU)
    BYTE cpuSha[32]{}, gpuSha[32]{}, boardSha[32]{}, diskSha[32]{}, v1Sha[32]{};
    ComputeSha256Bytes(cpuSig.data(), cpuSig.size(), cpuSha);
    ComputeSha256Bytes(gpuSig.data(), gpuSig.size(), gpuSha);
    ComputeSha256Bytes(boardSig.data(), boardSig.size(), boardSha);
    if (diskAvail) ComputeSha256Bytes(diskSig.data(), diskSig.size(), diskSha);
    ComputeSha256Bytes(hb.v1.data(), hb.v1.size(), v1Sha);

    BYTE baseKeyMat[84]{}, sealKey[32]{};
    static constexpr char kBaseSalt[] = "CR1M_HWB_PUB_K1|";
    constexpr size_t kBaseSaltLen = sizeof(kBaseSalt) - 1;
    memcpy(baseKeyMat, kBaseSalt, kBaseSaltLen);
    memcpy(baseKeyMat + kBaseSaltLen, cpuSha, 32);
    memcpy(baseKeyMat + kBaseSaltLen + 32, gpuSha, 32);
    ComputeSha256Bytes(baseKeyMat, kBaseSaltLen + 64, sealKey);
    SecureZeroMemory(baseKeyMat, sizeof(baseKeyMat));

    std::string p1Dir = GetAppDataBaseDir();
    std::string p1    = p1Dir + "\\.hw_base_pub.dat";
    std::string p2Dir = GetProgramDataBaseDir();
    std::string p2    = p2Dir.empty() ? std::string("") : (p2Dir + "\\.pub_hw_base.dat");

    bool haveBase = false;
    HwBaselinePayload storedBase{};
    for (int idx = 0; idx < 2; ++idx) {
        const std::string& bp = (idx == 0) ? p2 : p1;
        if (bp.empty()) continue;
        bool ex = false;
        std::vector<uint8_t> bytes;
        if (ReadFileBytes(bp, bytes, ex) && ex && bytes.size() == sizeof(HwBaselineDiskBlob)) {
            HwBaselineDiskBlob b{};
            memcpy(&b, bytes.data(), sizeof(b));
            HwBaselinePayload pl{};
            if (SealOrOpenBaselineBlob(false, sealKey, pl, b)) {
                storedBase = pl;
                haveBase = true;
                break;
            }
        }
    }

    if (haveBase) {
        if (memcmp(storedBase.cpuSha, cpuSha, 32) == 0 && memcmp(storedBase.gpuSha, gpuSha, 32) == 0) {
            if (memcmp(storedBase.boardSha, boardSha, 32) != 0) hb.spoof.boardBaselineDrift = true;
            if (storedBase.hasDisk && diskAvail && memcmp(storedBase.diskSha, diskSha, 32) != 0) hb.spoof.diskBaselineDrift = true;
            if (memcmp(storedBase.v1Sha, v1Sha, 32) != 0) hb.spoof.osGuidDrift = true;
        }
    } else {
        HwBaselinePayload fresh{};
        fresh.magic = HW_BASE_MAGIC;
        fresh.version = 1;
        memcpy(fresh.cpuSha, cpuSha, 32);
        memcpy(fresh.gpuSha, gpuSha, 32);
        memcpy(fresh.boardSha, boardSha, 32);
        if (diskAvail) memcpy(fresh.diskSha, diskSha, 32);
        memcpy(fresh.v1Sha, v1Sha, 32);
        fresh.hasDisk = diskAvail ? 1 : 0;
        HwBaselineDiskBlob sb{};
        if (SealOrOpenBaselineBlob(true, sealKey, fresh, sb)) {
            if (!p1Dir.empty()) WriteFileBytesHidden(p1Dir, p1, &sb, sizeof(sb));
            if (!p2Dir.empty()) WriteFileBytesHidden(p2Dir, p2, &sb, sizeof(sb));
        }
    }

    SecureZeroMemory(sealKey, sizeof(sealKey));
    SecureZeroMemory(cpuSha, sizeof(cpuSha));
    SecureZeroMemory(gpuSha, sizeof(gpuSha));
    SecureZeroMemory(boardSha, sizeof(boardSha));
    SecureZeroMemory(diskSha, sizeof(diskSha));
    SecureZeroMemory(v1Sha, sizeof(v1Sha));
    WipeStr(cpuSig);
    WipeStr(boardSig);
    WipeStr(diskSig);
    return hb;
}

void PrintSpooferWarning(const SpoofReport& sp) {
    if (!sp.hasPurchaseWarning()) return;
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    ConPrint(TR("\n  [!] HARDWARE / SPOOFER WARNING DETECTED:\n      ",
                "\n  [!] \xD0\x9E\xD0\x91\xD0\x9D\xD0\x90\xD0\xA0\xD0\xA3\xD0\x96\xD0\x95\xD0\x9D \xD0\xA1\xD0\x9F\xD0\xA3\xD0\xA4\xD0\x95\xD0\xA0 / \xD0\x98\xD0\x97\xD0\x9C\xD0\x95\xD0\x9D\xD0\x95\xD0\x9D\xD0\x98\xD0\x95 \xD0\x9E\xD0\x91\xD0\x9E\xD0\xA0\xD0\xA3\xD0\x94\xD0\x9E\xD0\x92\xD0\x90\xD0\x9D\xD0\x98\xD0\xAF:\n      ") +
             (IsRu() ? sp.summaryRu() : sp.summaryEn()) + "\n");
    ConPrint(TR("      If an HWID spoofer is active (e.g. from another game), DISABLE IT and\n"
                "      REBOOT before activating your license key, or your key will bind to a temporary ID!\n",
                "      \xD0\x95\xD1\x81\xD0\xBB\xD0\xB8 \xD1\x83 \xD0\xB2\xD0\xB0\xD1\x81 \xD0\xB2\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD1\x91\xD0\xBD HWID-\xD1\x81\xD0\xBF\xD1\x83\xD1\x84\xD0\xB5\xD1\x80 (\xD0\xB4\xD0\xBB\xD1\x8F \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xBE\xD0\xB9 \xD0\xB8\xD0\xB3\xD1\x80\xD1\x8B), \xD0\x9E\xD0\xA2\xD0\x9A\xD0\x9B\xD0\xAE\xD0\xA7\xD0\x98\xD0\xA2\xD0\x95 \xD0\xB5\xD0\xB3\xD0\xBE \xD0\xB8\n"
                "      \xD0\x9F\xD0\x95\xD0\xA0\xD0\x95\xD0\x97\xD0\x90\xD0\x93\xD0\xA0\xD0\xA3\xD0\x97\xD0\x98\xD0\xA2\xD0\x95 \xD0\x9F\xD0\x9A \xD0\xBF\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB4 \xD0\xB0\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD0\xB5\xD0\xB9 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB0, \xD0\xB8\xD0\xBD\xD0\xB0\xD1\x87\xD0\xB5 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB6\xD0\xB5\xD1\x82\xD1\x81\xD1\x8F \xD0\xBA \xD0\xB2\xD1\x80\xD0\xB5\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xBD\xD0\xBE\xD0\xBC\xD1\x83 ID!\n"));
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

bool ConfirmSpooferBeforeBind(const HwidBundle& hb, bool nonInteractive) {
    if (!hb.spoof.hasPurchaseWarning()) return true;
    PrintSpooferWarning(hb.spoof);
    if (nonInteractive) return false;
    ConPrint(TR("  Continue binding this license key to your current hardware anyway? [Y/N]: ",
                "  \xD0\x92\xD1\x81\xD1\x91 \xD1\x80\xD0\xB0\xD0\xB2\xD0\xBD\xD0\xBE \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD1\x8F\xD0\xB7\xD0\xB0\xD1\x82\xD1\x8C \xD1\x8D\xD1\x82\xD0\xBE\xD1\x82 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD0\xBB\xD0\xB8\xD1\x86\xD0\xB5\xD0\xBD\xD0\xB7\xD0\xB8\xD0\xB8 \xD0\xBA \xD1\x82\xD0\xB5\xD0\xBA\xD1\x83\xD1\x89\xD0\xB5\xD0\xBC\xD1\x83 \xD0\xBE\xD0\xB1\xD0\xBE\xD1\x80\xD1\x83\xD0\xB4\xD0\xBE\xD0\xB2\xD0\xB0\xD0\xBD\xD0\xB8\xD1\x8E? [Y/N]: "));
    std::string ans;
    if (!std::getline(std::cin, ans)) return false;
    std::string trimmed = Trim(ans);
    std::string t = ToUpperAscii(trimmed);
    if (!t.empty() && (t[0] == 'Y' || trimmed.find("\xD0\x94") == 0 || trimmed.find("\xD0\xB4") == 0)) {
        return true;
    }
    ConPrint(TR("  [!] Activation cancelled. Disable spoofer, reboot, and paste your key again.\n\n",
                "  [!] \xD0\x90\xD0\xBA\xD1\x82\xD0\xB8\xD0\xB2\xD0\xB0\xD1\x86\xD0\xB8\xD1\x8F \xD0\xBE\xD1\x82\xD0\xBC\xD0\xB5\xD0\xBD\xD0\xB5\xD0\xBD\xD0\xB0. \xD0\x9E\xD1\x82\xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87\xD0\xB8\xD1\x82\xD0\xB5 \xD1\x81\xD0\xBF\xD1\x83\xD1\x84\xD0\xB5\xD1\x80, \xD0\xBF\xD0\xB5\xD1\x80\xD0\xB5\xD0\xB7\xD0\xB0\xD0\xB3\xD1\x80\xD1\x83\xD0\xB7\xD0\xB8\xD1\x82\xD0\xB5 \xD0\x9F\xD0\x9A \xD0\xB8 \xD0\xB2\xD1\x81\xD1\x82\xD0\xB0\xD0\xB2\xD1\x8C\xD1\x82\xD0\xB5 \xD0\xBA\xD0\xBB\xD1\x8E\xD1\x87 \xD1\x81\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xB0.\n\n"));
    return false;
}

} // namespace cr1m
