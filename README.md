# CR1M Pro Mod (Source-Available)

Native C++20 external engine optimizer for **World of Tanks Blitz PC** supporting Microsoft Store (`x64`), Steam (`x86` WOW64), and Wargaming Game Center (`x86` WOW64).

Official prebuilt releases are available at **[https://cr1m.net](https://cr1m.net)**.

---

## Why This Repository Is Public

CR1M Pro Mod modifies `wotblitz.exe` in memory at runtime to fix frame pacing, camera input scaling, and tank-spotting hitches. Because unsigned native Windows binaries that touch game process memory are understandably scrutinized by players, the full engine, VRR, hardware-audit, and client-side verification source code is published here so anyone can inspect every single line and confirm:

- **Zero malware, spyware, keyloggers, or hidden network exfiltration.**
- **Zero gameplay cheats** (no aimbot, no ESP/wallhack, no dispersion/reload/speed hacks, no early spotting — spotting remains 100% server-authoritative).
- **Clean, reversible runtime patches** with full backup-and-rollback support (`RevertModEffects`).

---

## What the Mod Actually Does

1. **Precision Pure User-Mode QPC Frame Pacer (`src/engine/pacer.cpp`):**
   - Unlocks the engine framerate limit cleanly up to a VRR-safe ceiling (`<= 154 FPS`) adapted to the attached display refresh rate.
   - Replaces coarse integer `1000 / fps` + `Sleep()` frame pacing in `DAVA::EngineBackend::Run` (Loop B) with an inline user-mode `QueryPerformanceCounter` + hardware `PAUSE` (`F3 90`) spin cave, eliminating Windows 11 `15.625 ms` timer-coalescing frame drops.
   - Forces `DAVA::IsRunningOnWin10()` to return `true` so DX11 Flip Model (`DXGI_SWAP_EFFECT_FLIP_DISCARD`) stays enabled.
2. **Precision 1:1 Linear Mouse Aim (`src/engine/patcher_x64.cpp`, `src/engine/patcher_x86.cpp`):**
   - Bypasses the 2-frame mouse velocity smear filter in `BattleCamera::Rotate` while preserving Right-Click Free-Look and live FOV scaling.
   - Locks the camera acceleration factor (`addss` → `movss`) to an invariant `1.0f`.
   - Removes `roundf` step quantization and redirects the hardcoded `0.1°` camera snap deadzone in `BattleCamera::Update` and `BattleCamera::UpdateRotation` to `0.0°`.
3. **Tank-Spotting & First-Spot Camouflage Hitch Reduction (`src/engine/patcher_*.cpp`):**
   - Deduplicates redundant `SilhouetteSystem` material rebuild passes on spot/re-spot (`SilVisDup`, `SilAddDedup`, `SilAddTail`).
   - NOPs `CamouflageApplier::RemoveCamouflageFlags` / `RestoreCamouflageFlags` around `PreBuildMaterials` in `GameScene::PrecacheTankModel` so camouflaged shaders compile during battle load instead of stalling on first spot.
   - Live self-heals deprecated `RemoveEntity` cache patches (`SilKeepCacheHeal`) to prevent tank-destruction freezes.
4. **Hardware Topology, VRR & OS Scheduling (`src/platform/vrr.cpp`, `src/engine/patcher_x86.cpp`):**
   - Audits Windows DirectX VRR, DXGI Tearing, AMD FreeSync (via ADLX), and NVIDIA G-SYNC/VRR (via NVAPI DRS) — with automatic Hybrid Optimus/MSHybrid safety to prevent cross-adapter DWM flip contention.
   - Configures per-EXE DirectX GPU preferences (`UserGpuPreferences`), disables GameDVR, disables Win11 power/timer throttling, and boosts game process + main render thread priority.
5. **Client Verification & 15-Minute Free Test Drive (`src/auth/`):**
   - Uses an embedded RSA-2048 public key (zero private secrets in the client) to verify signed offline receipts bound to a BIOS-update-safe physical silicon fingerprint, with signed fail-open status checks and a 15-minute Free Test Drive.

---

## Transparency, Network Activity & Antivirus Disclosure

- **Exact Network Activity (2 HTTPS hosts only — zero telemetry or analytics):**
  1. `https://cr1m.net` (`POST /api/license/activate` and `POST /api/license/status`) — license activation and signed fail-open revocation checks in `src/auth/license.cpp`.
  2. `https://www.microsoft.com` (`HEAD /` header `Date` read only) — UTC clock-tamper verification during the 15-minute Free Test Drive in `src/auth/trial.cpp`.
  - Zero background services, zero scheduled tasks, zero crash telemetry, and zero file/account uploads.
- **Why Antivirus Heuristics May Flag This Mod:**
  - `NtSuspendProcess` / `VirtualAllocEx` / `WriteProcessMemory` (`src/core/win_runtime.cpp`, `src/engine/aob.cpp`, `src/engine/pacer.cpp`): used strictly to pause `wotblitz.exe` for ~1 ms, write verified byte patches, and allocate the 4 KB QPC frame-pacer cave.
  - `GetSystemFirmwareTable` / `DeviceIoControl` (`src/auth/hwid.cpp`): read-only SMBIOS & disk serial queries used strictly to compute a local SHA-256 hardware fingerprint for license binding and spoofer warnings.
- **Windows Registry & Local State (Zero Startup / COM Persistence):**
  - Performance tuning writes `HKCU\Software\Microsoft\DirectX\UserGpuPreferences` (GPU preference, Flip model, VRR) and `HKCU\System\GameConfigStore` (`GameDVR`), and stores user config/language/license cache in `%APPDATA%\CR1M_Pro_Mod\`.
  - During the 15-minute Free Test Drive, `src/auth/trial.cpp` stores a 76-byte encrypted binary countdown record (`ConfigData` under a dedicated `CLSID` key plus hidden local cache files) solely to track trial elapsed time. **No `InprocServer32`, COM server, DLL hook, Run key, or startup persistence is ever created.**
- **EULA Notice:** Although CR1M Pro Mod is strictly performance- and bugfix-oriented with zero cheat features, modifying game memory at runtime may conflict with Wargaming's EULA. Use at your own discretion.

---

## Repository Layout

```text
include/cr1m/
  build_config.hpp   # Toolchain, C++20, and compile-time configuration guards
  auth_proof.hpp     # Move-only authorization capability token
  win_runtime.hpp    # Win32 / NT process & memory helpers
  util.hpp           # UTF-8/16, JSON, atomic file I/O, hex & constant-time helpers
  i18n.hpp           # Auto-detected EN/RU console localization
  config.hpp         # config.txt parser
  hwid.hpp           # Silicon fingerprint (CPUID/SMBIOS/DXGI/disk) & spoofer audit
  auth.hpp           # Client-side RSA-2048 receipt & signed status verification
  trial.hpp          # 15-minute Free Test Drive & live rollback watchdog
  vrr.hpp            # Refresh rate, GPU topology, DXGI/ADLX/NVAPI VRR preflight
  clients.hpp        # MS Store (x64), Steam (x86), and WGC (x86) discovery/launch
  aob.hpp            # Single-read wildcard/alternation AOB scanner & PE/IAT parser
  pacer.hpp          # Pure user-mode QPC + PAUSE x64/x86 code cave emitters
  patcher.hpp        # System priority tweaks, rollback, and x64/x86 engine patchers

src/
  core/              # win_runtime.cpp, util.cpp, i18n.cpp, config.cpp
  auth/              # hwid.cpp, license.cpp, trial.cpp, trial_watchdog.cpp
  platform/          # vrr.cpp, clients.cpp
  engine/            # aob.cpp, pacer.cpp, patcher_x64.cpp, patcher_x86.cpp
  main.cpp           # Application entry point
```

---

## Official Builds & Licensing

- **Platform:** Windows 10/11 x64, written in C++20 for `x86_64` MinGW-w64 Clang.
- **No precompiled executables or build scripts are provided in this repository.** Official ready-to-run releases are distributed exclusively via **[https://cr1m.net](https://cr1m.net)**.
- **License:** Governed by the **[CR1M Source-Available License v1.0](LICENSE)**. You may inspect, audit, and compile this source code strictly for personal non-commercial use on your own PC. **Redistributing compiled binaries, modified builds, or forks (free or paid) is strictly prohibited.**
- **Read-Only Source Mirror & Support:** This repository is a read-only source transparency mirror and does not accept unsolicited pull requests. For bug reports, security disclosures, or licensing questions, contact **[support@cr1m.net](mailto:support@cr1m.net)** (see [SECURITY.md](SECURITY.md)).
