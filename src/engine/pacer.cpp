// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#include "cr1m/pacer.hpp"
#include "cr1m/win_runtime.hpp"

namespace cr1m {

std::vector<uint8_t> BuildX64Cave(uint32_t targetFps, uint64_t ticksPerFrame,
                                  uint64_t pIatQpc, uint64_t pIatSleep,
                                  const AuthProof& proof) {
    const uint32_t magic = proof.deriveCaveMagic();
    if (magic == 0) return {};

    CaveBuilder c(384);
    // 0x60 byte header shared with x86 ("CRM5")
    c.u32(magic); c.u32(targetFps);                 // +0x00, +0x04
    c.u64(ticksPerFrame); c.u64(0);                 // +0x08 ticksPerFrame, +0x10 reserved
    c.u64(0);                                       // +0x18 lastTick
    c.u64(pIatQpc); c.u64(pIatSleep);               // +0x20, +0x28
    c.u64(0); c.u64(0); c.u64(0); c.u64(0);         // +0x30..0x48 reserved
    c.u64(0); c.u64(0);                             // +0x50 trialLeaseQpc, +0x58 reserved
    c.padTo(0x60);

    // Prologue: push rbx, rsi, rdi; sub rsp, 0x30; mov ebx, ecx (rsp % 16 == 0)
    // Stack slots: [rsp+0x00..0x1F] Win64 shadow space, [rsp+0x20] qpcTmp
    c.bytes({0x53, 0x56, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0xD9});
    c.bytes({0x48, 0x8B, 0x35}); c.rip32(0x08);     // mov rsi, [ticksPerFrame]
    c.bytes({0x48, 0x85, 0xF6});                    // test rsi, rsi
    size_t jz_fb = c.jcc32(0x84);                   // jz fallback (ticks == 0 or reverted)
    c.bytes({0x83, 0xFB, 0x19});                    // cmp ebx, 25
    size_t jae_fb = c.jcc32(0x83);                  // jae fallback (dwMs >= 25 -> Sleep)

    // QPC(&qpcTmp) -> rax = now
    c.bytes({0x48, 0x8D, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0x05}); c.rip32(0x20);
    c.bytes({0xFF, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20});

    // Trial watchdog lease check at +0x50 (0 = licensed unlimited)
    c.bytes({0x48, 0x8B, 0x0D}); c.rip32(0x50);     // mov rcx, [trialLeaseQpc]
    c.bytes({0x48, 0x85, 0xC9});                    // test rcx, rcx
    size_t jz_lease_ok = c.jcc32(0x84);
    c.bytes({0x48, 0x39, 0xC8});                    // cmp rax, rcx
    size_t jae_lease_exp = c.jcc32(0x83);
    size_t lease_ok = c.pos();
    c.patch32(jz_lease_ok, lease_ok);

    // rdi = lastTick; if (!rdi) store now
    c.bytes({0x48, 0x8B, 0x3D}); c.rip32(0x18);
    c.bytes({0x48, 0x85, 0xFF});
    size_t jz_store = c.jcc32(0x84);

    // target = lastTick + ticksPerFrame; if (now >= target) anchor lastTick = now immediately
    c.bytes({0x48, 0x01, 0xF7, 0x48, 0x39, 0xF8});  // add rdi, rsi; cmp rax, rdi
    size_t jae_store = c.jcc32(0x83);

    // Pure QPC + PAUSE loop: <1us frame interval precision, zero OS timer overshoot
    size_t spin_loop = c.pos();
    c.bytes({0xF3, 0x90});                          // pause
    c.bytes({0x48, 0x8D, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0x05}); c.rip32(0x20);
    c.bytes({0xFF, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20});
    c.bytes({0x48, 0x39, 0xF8});                    // cmp rax, rdi
    size_t jb_spin = c.jcc32(0x82);

    // Always anchor lastTick = now (prevents catchup frames < 6.49ms colliding with VSync)
    size_t store_now = c.pos();
    c.bytes({0x48, 0x89, 0x05}); c.rip32(0x18);     // mov [lastTick], rax

    size_t done = c.pos();
    c.bytes({0x48, 0x83, 0xC4, 0x30, 0x5F, 0x5E, 0x5B, 0xC3});

    size_t fallback = c.pos();
    c.bytes({0x89, 0xD9, 0x48, 0x8B, 0x05}); c.rip32(0x28);
    c.bytes({0xFF, 0x10});
    size_t jmp_done = c.jmp32();
    c.patch32(jmp_done, done);

    c.patch32(jz_fb, fallback);     c.patch32(jae_fb, fallback);
    c.patch32(jae_lease_exp, fallback);
    c.patch32(jz_store, store_now); c.patch32(jae_store, store_now);
    c.patch32(jb_spin, spin_loop);
    return c.buf;
}

std::vector<uint8_t> BuildX86Cave(uint32_t caveBase32, uint32_t targetFps, uint64_t ticksPerFrame,
                                  uint32_t pIatQpc, uint32_t pIatSleep,
                                  uint32_t switchJoinVa,
                                  const AuthProof& proof) {
    const uint32_t magic = proof.deriveCaveMagic();
    if (magic == 0) return {};

    CaveBuilder c(768);
    uint32_t aTicksLo = caveBase32 + 0x08, aTicksHi = caveBase32 + 0x0C;
    uint32_t aLastLo  = caveBase32 + 0x18, aLastHi  = caveBase32 + 0x1C;
    uint32_t aQpcPtr  = caveBase32 + 0x20, aSlpPtr  = caveBase32 + 0x28;
    uint32_t aLeaseLo = caveBase32 + 0x50, aLeaseHi = caveBase32 + 0x54;

    c.u32(magic); c.u32(targetFps);                         // +0x00, +0x04
    c.u64(ticksPerFrame); c.u64(0);                         // +0x08 ticksPerFrame, +0x10 reserved
    c.u64(0);                                               // +0x18 lastTick
    c.u64(static_cast<uint64_t>(pIatQpc));                  // +0x20
    c.u64(static_cast<uint64_t>(pIatSleep));                // +0x28
    c.u64(0); c.u64(0); c.u64(0); c.u64(0);                 // +0x30..0x48
    c.u64(0); c.u64(0);                                     // +0x50 trialLeaseQpc, +0x58
    c.padTo(0x60);

    // Prologue: push ebx, esi, edi; sub esp, 0x0C ([esp+0x1C] = dwMs)
    // Stack locals: [0x00]=qpcTmp(8), [0x08]=origDwMs(4)
    c.bytes({0x53, 0x56, 0x57, 0x83, 0xEC, 0x0C});
    c.bytes({0x8B, 0x44, 0x24, 0x1C, 0x89, 0x44, 0x24, 0x08}); // save origDwMs
    c.bytes({0x8B, 0x0D}); c.u32(aTicksLo);
    c.bytes({0x0B, 0x0D}); c.u32(aTicksHi);
    size_t jz_fb = c.jcc32(0x84);
    c.bytes({0x83, 0x7C, 0x24, 0x08, 0x19});                   // cmp dword ptr [esp+8], 25
    size_t jae_fb = c.jcc32(0x83);

    // QPC(&qpcTmp) -> edx:eax = now
    c.bytes({0x8D, 0x04, 0x24, 0x50, 0xA1}); c.u32(aQpcPtr); c.bytes({0xFF, 0x10});
    c.bytes({0x8B, 0x44, 0x24, 0x00, 0x8B, 0x54, 0x24, 0x04});

    // Trial watchdog lease check at +0x50 (0 = licensed unlimited)
    c.bytes({0x8B, 0x0D}); c.u32(aLeaseLo);
    c.bytes({0x8B, 0x1D}); c.u32(aLeaseHi);
    c.bytes({0x89, 0xCE, 0x09, 0xDE});
    size_t jz_l_ok = c.jcc32(0x84);
    c.bytes({0x39, 0xDA});
    size_t ja_l_exp = c.jcc32(0x87);
    size_t jb_l_ok  = c.jcc32(0x82);
    c.bytes({0x39, 0xC8});
    size_t jae_l_exp = c.jcc32(0x83);
    size_t lease_ok = c.pos();
    c.patch32(jz_l_ok, lease_ok);
    c.patch32(jb_l_ok, lease_ok);

    // edi:esi = lastTick
    c.bytes({0x8B, 0x35}); c.u32(aLastLo);
    c.bytes({0x8B, 0x3D}); c.u32(aLastHi);
    c.bytes({0x89, 0xF1, 0x09, 0xF9});
    size_t jz_st = c.jcc32(0x84);

    // target += ticks
    c.bytes({0x03, 0x35}); c.u32(aTicksLo);
    c.bytes({0x13, 0x3D}); c.u32(aTicksHi);

    // if (now >= target) goto store_now
    c.bytes({0x39, 0xFA});
    size_t ja_st = c.jcc32(0x87);
    size_t jb_sp = c.jcc32(0x82);
    c.bytes({0x39, 0xF0});
    size_t jae_st = c.jcc32(0x83);

    size_t spin_loop = c.pos();
    c.bytes({0xF3, 0x90});
    c.bytes({0x8D, 0x04, 0x24, 0x50, 0xA1}); c.u32(aQpcPtr); c.bytes({0xFF, 0x10});
    c.bytes({0x8B, 0x44, 0x24, 0x00, 0x8B, 0x54, 0x24, 0x04});
    c.bytes({0x39, 0xFA});
    size_t jb_sp2 = c.jcc32(0x82);
    size_t ja_st2 = c.jcc32(0x87);
    c.bytes({0x39, 0xF0});
    size_t jb_sp3 = c.jcc32(0x82);

    size_t store_now = c.pos();
    c.bytes({0xA3}); c.u32(aLastLo);
    c.bytes({0x89, 0x15}); c.u32(aLastHi);

    size_t done = c.pos();
    c.bytes({0x83, 0xC4, 0x0C, 0x5F, 0x5E, 0x5B, 0xC2, 0x04, 0x00});

    size_t fallback = c.pos();
    c.bytes({0xFF, 0x74, 0x24, 0x08, 0xA1}); c.u32(aSlpPtr); c.bytes({0xFF, 0x10});
    size_t jmp_done2 = c.jmp32(); c.patch32(jmp_done2, done);

    c.patch32(jz_fb, fallback);     c.patch32(jae_fb, fallback);
    c.patch32(ja_l_exp, fallback);  c.patch32(jae_l_exp, fallback);
    c.patch32(jz_st, store_now);    c.patch32(ja_st, store_now);
    c.patch32(jb_sp, spin_loop);    c.patch32(jae_st, store_now);
    c.patch32(jb_sp2, spin_loop);   c.patch32(ja_st2, store_now);
    c.patch32(jb_sp3, spin_loop);

    c.padTo(0x280);
    c.u8(0xBF); c.u32(targetFps);
    uint32_t jmpNext = caveBase32 + static_cast<uint32_t>(c.pos()) + 5;
    c.u8(0xE9); c.u32(switchJoinVa - jmpNext);
    return c.buf;
}

uintptr_t AllocNearModule(HANDLE hp, uintptr_t targetAddr, SIZE_T size) {
    uintptr_t minAddr = (targetAddr > 0x60000000ULL) ? (targetAddr - 0x60000000ULL) : 0x10000ULL;
    uintptr_t maxAddr = targetAddr + 0x60000000ULL;
    MEMORY_BASIC_INFORMATION mbi{};
    for (uintptr_t addr = minAddr; addr < maxAddr; ) {
        if (!VirtualQueryEx(hp, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= 0x10000) {
            uintptr_t tryAddr = (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + 0xFFFFULL) & ~0xFFFFULL;
            if (tryAddr + size <= reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize) {
                LPVOID p = runtime::DynVirtualAllocEx(hp, reinterpret_cast<LPVOID>(tryAddr), size,
                                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return reinterpret_cast<uintptr_t>(p);
            }
        }
        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr <= reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;
    }
    return 0;
}

} // namespace cr1m
