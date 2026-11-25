# CR1M Pro Mod (Source Available)

Native C++20 external engine optimizer for **World of Tanks Blitz PC** supporting Microsoft Store (`x64`), Steam (`x86` WOW64), and Wargaming Game Center (`x86` WOW64).

Official prebuilt releases are available at **[https://cr1m.net](https://cr1m.net)**.

---

## Why This Repository Is Public

CR1M Pro Mod modifies `wotblitz.exe` in memory at runtime to fix frame pacing, camera input scaling, and tank spotting hitches. Because unsigned native Windows binaries that touch game process memory are understandably scrutinized by players, the full engine, VRR, hardware audit, and client side verification source code is published here so anyone can inspect every single line and confirm:

- **Zero malware, spyware, keyloggers, or hidden network exfiltration.**
- **Zero gameplay cheats** (no aimbot, no ESP or wallhack, no dispersion, reload, or speed hacks, and no early spotting; spotting remains 100% server authoritative).
- **Clean, reversible runtime patches** with full backup and rollback support (`RevertModEffects`).

---

## What the Mod Actually Does

1. **Precision Pure User Mode QPC Frame Pacer (`src/engine/pacer.cpp`):**
   - Unlocks the engine framerate limit cleanly up to a VRR safe ceiling (`<= 154 FPS`) adapted to the attached display refresh rate.
   - Replaces coarse integer `1000 / fps` + `Sleep()` frame pacing in `DAVA::EngineBackend::Run` (Loop B) with an inline user mode `QueryPerformanceCounter` + hardware `PAUSE` (`F3 90`) spin cave, eliminating Windows 11 `15.625 ms` timer coalescing frame drops.
   - Forces `DAVA::IsRunningOnWin10()` to return `true` so DX11 Flip Model (`DXGI_SWAP_EFFECT_FLIP_DISCARD`) stays enabled.
2. **Precision 1:1 Linear Mouse Aim (`src/engine/patcher_x64.cpp`, `src/engine/patcher_x86.cpp`):**
   - Bypasses the 2 frame mouse velocity smear filter in `BattleCamera::Rotate` while preserving Right Click Free Look and live FOV scaling.
   - Locks the camera acceleration factor (`addss` to `movss`) to an invariant `1.0f`.
   - Removes `roundf` step quantization and redirects the hardcoded `0.1°` camera snap deadzone in `BattleCamera::Update` and `BattleCamera::UpdateRotation` to `0.0°`.
3. **Tank Spotting & First Spot Camouflage Hitch Reduction (`src/engine/patcher_*.cpp`):**
   - Deduplicates redundant `SilhouetteSystem` material rebuild passes on spot and respot (`SilVisDup`, `SilAddDedup`, `SilAddTail`).
   - NOPs `CamouflageApplier::RemoveCamouflageFlags` / `RestoreCamouflageFlags` around `PreBuildMaterials` in `GameScene::PrecacheTankModel` so camouflaged shaders compile during battle load instead of stalling on first spot.
   - Live self heals deprecated `RemoveEntity` cache patches (`SilKeepCacheHeal`) to prevent tank destruction freezes.
4. **Hardware Topology, Display EDID VRR & OS Scheduling (`src/platform/vrr.cpp`, `src/engine/patcher_x86.cpp`):**
   - Reads primary monitor EDID hardware VRR capabilities via `QueryDisplayConfig` (DisplayID 2.0 FreeSync, CTA 861 FreeSync VSDB, HDMI 2.1 VRR VSDB, and EDID 1.4 DisplayPort Adaptive Sync) so fixed refresh panels are never prompted unnecessarily.
   - Audits Windows DirectX VRR, DXGI Tearing, AMD FreeSync (via ADLX), and NVIDIA VRR / GSync (via NVAPI DRS, catching both `OFF` and `FULLSCREEN ONLY` on VRR capable direct displays), with automatic Hybrid Optimus and MSHybrid safety and optional one key launch of NVIDIA App, NVIDIA Control Panel, or AMD Adrenalin.
   - Configures per EXE DirectX GPU preferences (`UserGpuPreferences`), disables GameDVR, disables Win11 power and timer throttling, and boosts game process and main render thread priority.
5. **Client Verification, Signed OTA Updates & 15 Minute Free Test Drive (`src/auth/`):**
   - Uses an embedded RSA 2048 public key (zero private secrets in the client) to verify signed offline receipts bound to a BIOS update safe physical silicon fingerprint, with signed fail open status checks and a 15 minute Free Test Drive.
   - Runs a zero latency background check against `GET https://cr1m.net/api/client/release` (RSA 2048 signed release manifest) so users can update in place with one keypress (`U` + `ENTER`, verified via PE64 header + Windows CNG SHA 256 + atomic `MoveFileExW` swap, zero shell scripts) whenever a new build drops.

---

## Update Log

### v2.4.0 (2026 11 25)
- **Three Tier Update Resilient Signature Engine:** Added hardened register tolerant Tier 1 AOBs, Tier 2 structural resolvers anchored on `KERNEL32!Sleep` IAT xrefs + `1000 / idiv`, call graphs, `.rdata` `0.0f` scans, and dynamic `x86` epilogue calculation, plus Tier 3 fail open RSA 2048 signed remote signature hotfix manifests with per architecture anti rollback caching.
- **Full World of Tanks Blitz 11.22 Support Across All Three PC Editions:**
  - **Microsoft Store (`x64` `11.22.235.0`):** Supported REX prefixed `idiv` (`41 F7 FE`) and shifted `cmovl` register allocation in both Tier 1 and Tier 2 `x64_LoopB` resolvers.
  - **Steam (`x86` `11.22.0.1379`) & WGC (`x86` `11.22.0.30`):** Supported XMM register shifts on `UpdSnap1`/`UpdSnap3`, both 48 byte and 54 byte `xmm1` stack spilled `UpdRoundf` layouts (preserving pitch stack data and idempotent re attach), and dual site split `UpdRotSnap` + `UpdRotSnap2`.
- **Zero Latency Signed OTA Self Updater:** Background release check runs in parallel with `[1/5]` and `[2/5]` (0 ms overhead when current), prompts `[U] Update Now / [ENTER] Skip` right before `[3/5]` for both Licensed and Test Drive users (and keeps `U` available at the end prompt), verifies RSA 2048 + exact byte length + PE64 + Windows CNG SHA 256, swaps atomically via native `MoveFileExW`, relaunches via `CreateProcessW` preserving CLI arguments, and retries `.old` cleanup cleanly on next start.
- **Primary Monitor Hardware VRR / GSync / FreeSync Detection:** Added fast native `QueryDisplayConfig` + primary EDID VRR range detection (`Display VRR Cap`), suppressed prompts on fixed refresh displays, detected NVIDIA `FULLSCREEN ONLY` (`1`) vs `FULLSCREEN + WINDOWED` (`2`) on VRR capable direct displays, and added `[O]` shortcut to open NVIDIA App, NVIDIA Control Panel, or AMD Adrenalin.
- **Interactive Client Switcher & Safeguards:** Replaced the static exit pause with an interactive client switcher (`Press ENTER to close or press a letter (M / S / W) to launch a different client`), added honest per subsystem status (`[SUCCESS]` / `[PARTIAL]` / `[FAILED]`) with a direct `cr1m.net` update link, and added a Free Test Drive partial guard that reverts hooks with 0 minutes consumed if core engine or pacer signatures mismatch.

### v2.3
- Published the modular 14 header / 15 source C++20 source available transparency mirror with Pure User Mode QPC frame pacing (`<= 154 FPS`), 1:1 linear mouse aim, tank spotting hitch reduction, Hybrid Optimus VRR preflight, and RSA 2048 offline receipt verification.

---

## Transparency, Network Activity & Antivirus Disclosure

- **Exact Network Activity (2 HTTPS hosts only, zero telemetry or analytics):**
  1. `https://cr1m.net` (`POST /api/license/activate`, `POST /api/license/status`, `GET /api/client/release`, optional `GET /api/client/sigs`, and user confirmed official executable download under `/releases/`): license activation, signed fail open revocation checks, RSA 2048 signed OTA release discovery and binary download (only when the user explicitly presses `U`), and RSA 2048 signed signature hotfix manifests (queried only if a local signature misses after a game update) in `src/auth/license.cpp`.
  2. `https://www.microsoft.com` (`HEAD /` header `Date` read only): UTC clock tamper verification during the 15 minute Free Test Drive in `src/auth/trial.cpp`.
  - Zero background services, zero scheduled tasks, zero crash telemetry, and zero file or account uploads.
- **Why Antivirus Heuristics May Flag This Mod:**
  - `NtSuspendProcess` / `VirtualAllocEx` / `WriteProcessMemory` (`src/core/win_runtime.cpp`, `src/engine/aob.cpp`, `src/engine/pacer.cpp`): used strictly to pause `wotblitz.exe` for ~1 ms, write verified byte patches, and allocate the 4 KB QPC frame pacer cave.
  - `GetSystemFirmwareTable` / `DeviceIoControl` (`src/auth/hwid.cpp`): read only SMBIOS and disk serial queries used strictly to compute a local SHA256 hardware fingerprint for license binding and spoofer warnings.
  - `WinHttpReadData` / `MoveFileExW` / `CreateProcessW` (`src/auth/license.cpp`): used strictly when the user explicitly presses `U` to install an RSA 2048 and Windows CNG SHA 256 verified update in place from `https://cr1m.net` (zero `cmd.exe`, `powershell.exe`, or batch scripts).
- **Windows Registry & Local State (Zero Startup or COM Persistence):**
  - Performance tuning writes `HKCU\Software\Microsoft\DirectX\UserGpuPreferences` (GPU preference, Flip model, VRR) and `HKCU\System\GameConfigStore` (`GameDVR`), reads primary monitor EDID bytes read only from `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\...\Device Parameters\EDID` (`src/platform/vrr.cpp`) to detect hardware VRR capability, and stores user config, language, signed signature cache, and license cache in `%APPDATA%\CR1M_Pro_Mod\`.
  - User confirmed OTA updates write a temporary `.new` file and rename the prior binary to `.old` next to the executable during atomic swap; the relaunched binary automatically deletes `.old` on startup.
  - During the 15 minute Free Test Drive, `src/auth/trial.cpp` stores a 76 byte encrypted binary countdown record (`ConfigData` under a dedicated `CLSID` key plus hidden local cache files) solely to track trial elapsed time. **No `InprocServer32`, COM server, DLL hook, Run key, or startup persistence is ever created.**
- **EULA Notice:** Although CR1M Pro Mod is strictly performance and bugfix oriented with zero cheat features, modifying game memory at runtime may conflict with Wargaming's EULA. Use at your own discretion.

---

## Repository Layout

```text
include/cr1m/
  build_config.hpp   # Toolchain, C++20, and compile time configuration guards
  auth_proof.hpp     # Move only authorization capability token
  win_runtime.hpp    # Win32 / NT process & memory helpers
  util.hpp           # UTF8/UTF16, JSON, atomic file I/O, hex & constant time helpers
  i18n.hpp           # Auto detected EN/RU console localization
  config.hpp         # config.txt parser
  hwid.hpp           # Silicon fingerprint (CPUID/SMBIOS/DXGI/disk) & spoofer audit
  auth.hpp           # RSA 2048 receipt, status, hotfix manifest & signed OTA updater
  trial.hpp          # 15 minute Free Test Drive & live rollback watchdog
  vrr.hpp            # Primary EDID VRR parser, GPU topology, DXGI/ADLX/NVAPI & GPU apps
  clients.hpp        # MS Store (x64), Steam (x86), and WGC (x86) discovery/launch
  aob.hpp            # Single read AOB scanner, PE/IAT structural & manifest rule parsers
  pacer.hpp          # Pure user mode QPC + PAUSE x64/x86 code cave emitters
  patcher.hpp        # System priority tweaks, rollback, and x64/x86 engine patchers

src/
  core/              # win_runtime.cpp, util.cpp, i18n.cpp, config.cpp
  auth/              # hwid.cpp, license.cpp, trial.cpp, trial_watchdog.cpp
  platform/          # vrr.cpp, clients.cpp
  engine/            # aob.cpp, pacer.cpp, patcher_x64.cpp, patcher_x86.cpp
  main.cpp           # Startup OTA gate, preflight, patching & interactive client switcher
```

---

## Official Builds & Licensing

- **Platform:** Windows 10/11 x64, written in C++20 for `x86_64` MinGW w64 Clang.
- **No precompiled executables or build scripts are provided in this repository.** Official ready to run releases are distributed exclusively via **[https://cr1m.net](https://cr1m.net)**.
- **License:** Governed by the **[CR1M Source Available License v1.0](LICENSE)**. You may inspect, audit, and compile this source code strictly for personal noncommercial use on your own PC. **Redistributing compiled binaries, modified builds, or forks (free or paid) is strictly prohibited.**
- **Read Only Source Mirror & Support:** This repository is a read only source transparency mirror and does not accept unsolicited pull requests. For bug reports, security disclosures, or licensing questions, contact **[support@cr1m.net](mailto:support@cr1m.net)** (see [SECURITY.md](SECURITY.md)).
