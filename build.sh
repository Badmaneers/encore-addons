#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# build.sh — Cross-compile bypass_daemon for Android ARM64 and
#             package it into a flashable Magisk/KSU module zip.
#
# Usage:
#   ./build.sh              Build binary only
#   ./build.sh --pack       Build binary + package module zip
#   ./build.sh --module     Package module zip only (skip compile)
#   ./build.sh --clean      Remove all build artifacts
#   ./build.sh --help       Show this help
# ─────────────────────────────────────────────────────────────────────
set -e

PROJECT="$(cd "$(dirname "$0")" && pwd)"
SRC="$PROJECT/src"
INC="$PROJECT/include"
OUTDIR="$PROJECT/build_android"
DEPS="$PROJECT/deps/install"
MODULE="$PROJECT/module"
OUTPUT="$PROJECT/encore_bypass_charging.zip"

NDK="/home/zylex/Android/Sdk/ndk/27.0.12077973"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
CC="$TOOLCHAIN/bin/clang"
SYSROOT="$TOOLCHAIN/sysroot"

BINARY="$OUTDIR/bypass_daemon"

# ─── Usage ───────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "  (no flag)     Build the Android ARM64 binary"
    echo "  --pack        Build binary + package flashable module zip"
    echo "  --module      Package module zip only (requires prior build)"
    echo "  --clean       Remove all build artifacts"
    echo "  --help, -h    Show this help"
    exit 0
}

# ─── Clean ───────────────────────────────────────────────────────────
do_clean() {
    echo "Cleaning build artifacts..."
    rm -rf "$OUTDIR"
    rm -f "$OUTPUT"
    rm -f "$MODULE/libs/arm64-v8a/bypass_chg"
    rm -f "$MODULE/checksums.sha256"
    echo "Done."
    exit 0
}

# ─── Compile ─────────────────────────────────────────────────────────
do_compile() {
    export PATH="$TOOLCHAIN/bin:$PATH"
    mkdir -p "$OUTDIR"

    echo "═══════════════════════════════════════════════════════════"
    echo "  Building bypass_daemon for Android ARM64 (API 34)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    for f in "$DEPS/lib/libcurl.a" "$DEPS/lib/libssl.a" "$DEPS/lib/libcrypto.a" \
             "$DEPS/include/curl/curl.h" "$DEPS/include/openssl/evp.h"; do
        if [ ! -f "$f" ]; then
            echo "ERROR: Missing dependency: $f"
            exit 1
        fi
    done

    SOURCES=(
        "$SRC/main.c"
        "$SRC/bypass_charging.c"
        "$SRC/license_manager.c"
        "$SRC/safety_monitor.c"
        "$SRC/device_probe.c"
        "$SRC/file_watcher.c"
        "$SRC/logging.c"
        "$SRC/file_io.c"
        "$SRC/crypto_utils.c"
        "$SRC/anti_tamper.c"
    )

    CFLAGS=(
        --sysroot="$SYSROOT"
        -target aarch64-linux-android34
        -I"$INC"
        -I"$DEPS/include"
        -O2
        -Wall -Wextra -Wno-unused-parameter
        -DANDROID
        -fPIE
        -fstack-protector-strong
        # Anti-RE: no frame pointers, no debug info, obfuscate string refs
        -fomit-frame-pointer
        -fvisibility=hidden
        -fdata-sections -ffunction-sections
    )

    echo "[1/3] Compiling sources..."
    OBJS=()
    for src in "${SOURCES[@]}"; do
        base=$(basename "$src" .c)
        obj="$OUTDIR/${base}.o"
        echo "  CC  $base.c"
        "$CC" "${CFLAGS[@]}" -c "$src" -o "$obj"
        OBJS+=("$obj")
    done

    echo ""
    echo "[2/3] Linking bypass_daemon (static curl + openssl)..."
    "$CC" \
        --sysroot="$SYSROOT" \
        -target aarch64-linux-android34 \
        -pie \
        -Wl,--gc-sections \
        "${OBJS[@]}" \
        "$DEPS/lib/libcurl.a" \
        "$DEPS/lib/libssl.a" \
        "$DEPS/lib/libcrypto.a" \
        -lz -ldl \
        -o "$BINARY"

    echo ""
    echo "[3/3] Stripping..."
    cp "$BINARY" "$BINARY.debug"
    "$TOOLCHAIN/bin/llvm-objcopy" --strip-all "$BINARY"

    BIN_SIZE=$(ls -lh "$BINARY" | awk '{print $5}')
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Output: $BINARY ($BIN_SIZE)"
    file "$BINARY"
    echo "═══════════════════════════════════════════════════════════"
}

# ─── Package module ──────────────────────────────────────────────────
do_package() {
    if [ ! -f "$BINARY" ]; then
        echo "ERROR: $BINARY not found. Build first with: $0"
        exit 1
    fi

    echo ""
    echo "Packaging flashable module..."
    mkdir -p "$MODULE/libs/arm64-v8a"
    cp "$BINARY" "$MODULE/libs/arm64-v8a/bypass_chg"
    chmod 755 "$MODULE/libs/arm64-v8a/bypass_chg"

    cd "$MODULE"

    # Generate checksums manifest at package time
    echo "[*] Computing SHA-256 checksums..."
    MANIFEST="checksums.sha256"
    rm -f "$MANIFEST"
    for f in \
        module.prop \
        service.sh \
        gamelist.txt \
        "libs/arm64-v8a/bypass_chg" \
        "META-INF/com/google/android/update-binary" \
        "META-INF/com/google/android/updater-script"
    do
        sha256sum "$f" >> "$MANIFEST"
    done

    rm -f "$OUTPUT"
    zip -r9 "$OUTPUT" \
        META-INF/com/google/android/update-binary \
        META-INF/com/google/android/updater-script \
        module.prop \
        service.sh \
        customize.sh \
        verify.sh \
        gamelist.txt \
        libs/arm64-v8a/bypass_chg \
        checksums.sha256

    ZIP_SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Module: $OUTPUT ($ZIP_SIZE)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Flash via Magisk/KernelSU:"
    echo "  adb push $OUTPUT /sdcard/"
    echo "  # Then install from Magisk Manager → Modules → Install from storage"
}

# ─── Main ────────────────────────────────────────────────────────────
case "${1:-build}" in
    --help|-h)  usage ;;
    --clean)    do_clean ;;
    --module)   do_package ;;
    --pack)     do_compile; do_package ;;
    build|"")   do_compile ;;
    *)          echo "Unknown option: $1"; usage ;;
esac
