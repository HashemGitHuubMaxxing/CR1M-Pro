// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/win_runtime.hpp"

namespace cr1m::runtime {

namespace {

WinApiTable gApi{};

FARPROC ResolveKernelFn(const char* name) {
    FARPROC f = NULL;
    if (gApi.hKernel32) f = GetProcAddress(gApi.hKernel32, name);
    if (!f && gApi.hKernelBase) f = GetProcAddress(gApi.hKernelBase, name);
    return f;
}

} // namespace

WinApiTable& Api() {
    return gApi;
}

bool InitWinApis() {
    if (gApi.ready) return true;
    gApi.hNtdll      = GetModuleHandleW(L"ntdll.dll");
    gApi.hKernel32   = GetModuleHandleW(L"kernel32.dll");
    gApi.hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (!gApi.hNtdll || !gApi.hKernel32) return false;

    gApi.pNtSuspend   = reinterpret_cast<FnNtSuspendResume>(GetProcAddress(gApi.hNtdll, "NtSuspendProcess"));
    gApi.pNtResume    = reinterpret_cast<FnNtSuspendResume>(GetProcAddress(gApi.hNtdll, "NtResumeProcess"));
    gApi.pSetProcInfo = reinterpret_cast<pfnSetProcessInformation>(ResolveKernelFn("SetProcessInformation"));
    gApi.pGetPkgFam   = reinterpret_cast<pfnGetPackagesByPackageFamily>(ResolveKernelFn("GetPackagesByPackageFamily"));

    gApi.ready = true;
    return true;
}

HANDLE DynOpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    return OpenProcess(access, inherit, pid);
}

LPVOID DynVirtualAllocEx(HANDLE hProc, LPVOID addr, SIZE_T size, DWORD allocType, DWORD prot) {
    return VirtualAllocEx(hProc, addr, size, allocType, prot);
}

BOOL DynVirtualProtectEx(HANDLE hProc, LPVOID addr, SIZE_T size, DWORD newProt, PDWORD oldProt) {
    return VirtualProtectEx(hProc, addr, size, newProt, oldProt);
}

BOOL DynWriteProcessMemory(HANDLE hProc, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T* written) {
    return WriteProcessMemory(hProc, addr, buf, size, written);
}

BOOL DynReadProcessMemory(HANDLE hProc, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* read) {
    return ReadProcessMemory(hProc, addr, buf, size, read);
}

HANDLE DynCreateToolhelp32Snapshot(DWORD flags, DWORD pid) {
    return CreateToolhelp32Snapshot(flags, pid);
}

BOOL DynProcess32FirstW(HANDLE snap, LPPROCESSENTRY32W entry) {
    return Process32FirstW(snap, entry);
}

BOOL DynProcess32NextW(HANDLE snap, LPPROCESSENTRY32W entry) {
    return Process32NextW(snap, entry);
}

BOOL DynModule32FirstW(HANDLE snap, LPMODULEENTRY32W entry) {
    return Module32FirstW(snap, entry);
}

BOOL DynModule32NextW(HANDLE snap, LPMODULEENTRY32W entry) {
    return Module32NextW(snap, entry);
}

BOOL DynThread32First(HANDLE snap, LPTHREADENTRY32 entry) {
    return Thread32First(snap, entry);
}

BOOL DynThread32Next(HANDLE snap, LPTHREADENTRY32 entry) {
    return Thread32Next(snap, entry);
}

BOOL DynQueryFullProcessImageNameW(HANDLE hProc, DWORD flags, LPWSTR path, PDWORD size) {
    return QueryFullProcessImageNameW(hProc, flags, path, size);
}

} // namespace cr1m::runtime
