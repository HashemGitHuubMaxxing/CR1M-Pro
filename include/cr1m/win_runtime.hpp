// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source-Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"

namespace cr1m::runtime {

using FnNtSuspendResume = LONG (NTAPI*)(HANDLE);

struct WinApiTable {
    bool ready = false;
    HMODULE hNtdll      = NULL;
    HMODULE hKernel32   = NULL;
    HMODULE hKernelBase = NULL;

    FnNtSuspendResume             pNtSuspend   = nullptr;
    FnNtSuspendResume             pNtResume    = nullptr;
    pfnSetProcessInformation      pSetProcInfo = nullptr;
    pfnGetPackagesByPackageFamily pGetPkgFam   = nullptr;
};

WinApiTable& Api();
bool InitWinApis();

HANDLE DynOpenProcess(DWORD access, BOOL inherit, DWORD pid);
LPVOID DynVirtualAllocEx(HANDLE hProc, LPVOID addr, SIZE_T size, DWORD allocType, DWORD prot);
BOOL   DynVirtualProtectEx(HANDLE hProc, LPVOID addr, SIZE_T size, DWORD newProt, PDWORD oldProt);
BOOL   DynWriteProcessMemory(HANDLE hProc, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T* written);
BOOL   DynReadProcessMemory(HANDLE hProc, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* read);
HANDLE DynCreateToolhelp32Snapshot(DWORD flags, DWORD pid);
BOOL   DynProcess32FirstW(HANDLE snap, LPPROCESSENTRY32W entry);
BOOL   DynProcess32NextW(HANDLE snap, LPPROCESSENTRY32W entry);
BOOL   DynModule32FirstW(HANDLE snap, LPMODULEENTRY32W entry);
BOOL   DynModule32NextW(HANDLE snap, LPMODULEENTRY32W entry);
BOOL   DynThread32First(HANDLE snap, LPTHREADENTRY32 entry);
BOOL   DynThread32Next(HANDLE snap, LPTHREADENTRY32 entry);
BOOL   DynQueryFullProcessImageNameW(HANDLE hProc, DWORD flags, LPWSTR path, PDWORD size);

} // namespace cr1m::runtime
