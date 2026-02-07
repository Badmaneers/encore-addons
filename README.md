# Encore Bypass Charging Addon

A Magisk/KernelSU module that automatically enables bypass charging when playing games, protecting battery health during intensive gaming sessions.

> **Reconstructed** from Ghidra pseudocode of the original ARM64 Android binary (v1.3) by rem01gaming.

## How It Works

When a game is detected in the foreground, the module writes to sysfs nodes to enable bypass charging — the device runs directly from the charger instead of the battery. When the game exits, normal charging resumes.

**Two operating modes:**

- **Encore Tweaks mode** — If [Encore Tweaks](https://github.com/Rem01Gaming/encore) is installed, bypass charging activates on Performance profile and deactivates on other profiles.
- **Standalone mode** — Polls every 15 seconds for foreground games from a configurable game list. Includes special MLBB thread detection for thread boosting.

## Project Structure

```
├── src/                    # C source files
│   ├── main.c              # Entry point, argument parsing, daemon loop
│   ├── bypass_charging.c   # Sysfs node operations for 49 bypass methods
│   ├── license_manager.c   # License verification (challenge-response protocol)
│   ├── safety_monitor.c    # Game detection, profile monitoring, periodic license recheck
│   ├── anti_tamper.c       # Anti-debug, anti-hook, integrity checks, booby traps
│   ├── device_probe.c      # Device serial, foreground app, system property detection
│   ├── file_io.c           # File read/write helpers with flock support
│   ├── file_watcher.c      # inotify-based file watcher for profile changes
│   ├── crypto_utils.c      # SHA-256 and HMAC utilities (OpenSSL wrapper)
│   └── logging.c           # Logging with timestamps and Android notification support
├── include/                # Header files
├── server/                 # License server (Python) — see server/README.md
├── module/                 # Magisk module template (service.sh, customize.sh, etc.)
├── deps/                   # Pre-built static libraries (libcurl, libssl, libcrypto)
├── build.sh                # Cross-compilation and packaging script
├── Android.mk              # ndk-build makefile
└── CMakeLists.txt          # CMake build (alternative)
```

## Requirements

- **Android NDK 27** (r27, API 34)
- **Linux host** for cross-compilation
- **Static libraries** in `deps/install/`:
  - `libcurl.a` (with SSL support)
  - `libssl.a` + `libcrypto.a` (OpenSSL)

## Building

```bash
# Release build (all protections enabled)
./build.sh

# Release build + flashable zip
./build.sh --pack

# Debug build (no license checks, no anti-tamper, debug symbols)
./build.sh --debug

# Debug build + flashable zip
./build.sh --pack --debug

# Package zip only (requires prior build)
./build.sh --module

# Clean build artifacts
./build.sh --clean
```

### Release vs Debug

| Feature | Release | Debug (`--debug`) |
|---|---|---|
| License verification | ✅ Enabled | ❌ Skipped |
| Anti-tamper checks | ✅ Enabled | ❌ Disabled |
| Optimization | `-O2` | `-O0 -g` |
| Symbol stripping | ✅ Stripped | ❌ Preserved |
| Anti-RE flags | ✅ `-fvisibility=hidden`, `--gc-sections` | ❌ None |

> ⚠️ **Never ship a debug build to end users.**

## Binary Usage

```bash
# Run the bypass test (detects supported bypass charging method)
su -c bypass_chg --test

# Check license status
su -c bypass_chg --license-check

# Run integrity diagnostics (identify anti-tamper false positives)
su -c bypass_chg --integrity-test

# Normal daemon mode (called by service.sh on boot)
su -c bypass_chg
```

## License Protocol

The binary communicates with a license server using a challenge-response protocol:

1. **Nonce request** — `GET /nonce` → server returns a timestamped single-use nonce
2. **License check** — `GET /{file_hash}/{serial}?nonce={nonce}`
3. **Response validation** — client computes `SHA256(file_hash + serial + salt + nonce)` and compares with constant-time comparison

On boot, the daemon retries up to 3 times (15s apart) if the network isn't ready. License is re-verified every 6 hours.

## Security

### Anti-Tamper (Release builds)
- **Debugger detection** — TracerPid monitoring, `/proc` scan for gdb/strace/frida-server
- **Framework detection** — `/proc/self/maps` scan for Frida agent, libgadget, substrate
- **Environment checks** — LD_PRELOAD hooking detection, emulator fingerprinting
- **Booby traps** — Honeypot functions (`bypass_license_check`, `force_license_ok`, etc.) that silently disable and remove the module
- **Salt obfuscation** — HMAC salt split into XOR-masked fragments, reconstructed at runtime

### Build Hardening (Release)
- `-fvisibility=hidden` — hide internal symbols
- `-fomit-frame-pointer` — hinder stack traces
- `-fdata-sections -ffunction-sections` + `--gc-sections` — strip unused code
- TLS 1.2 minimum, certificate verification, redirect limit

## Module Files

| File | Purpose |
|---|---|
| `module.prop` | Module metadata (id, name, version) |
| `service.sh` | Launched by Magisk on boot — starts the daemon |
| `customize.sh` | Installation script — runs during module flash |
| `verify.sh` | SHA-256 integrity verification during install |
| `gamelist.txt` | List of game package names for standalone mode |
| `checksums.sha256` | SHA-256 manifest of module files |

## Credits

- **Original author**: [rem01gaming](https://t.me/rem01schannel)
- **Reconstruction**: Badmaneers — reverse-engineered from Ghidra pseudocode
