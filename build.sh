#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# build.sh — Cross-compile bypass_daemon for Android ARM64 and
#             package it into a flashable Magisk/KSU module zip.
#
# Usage:
#   ./build.sh                    Build binary only (release)
#   ./build.sh --debug            Build debug binary (no license/anti-tamper)
#   ./build.sh --pack             Build release + package module zip
#   ./build.sh --pack --debug     Build debug + package module zip
#   ./build.sh --module           Package module zip only (skip compile)
#   ./build.sh --clean            Remove all build artifacts
#   ./build.sh --help             Show this help
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
    echo "Usage: $0 [OPTIONS...]"
    echo ""
    echo "  (no flag)           Build the Android ARM64 binary (release)"
    echo "  --debug             Build debug binary (no license checks, no anti-tamper)"
    echo "  --pack              Build binary + package flashable module zip"
    echo "  --pack --debug      Build debug + package module zip"
    echo "  --module            Package module zip only (requires prior build)"
    echo "  --clean             Remove all build artifacts"
    echo "  --help, -h          Show this help"
    echo ""
    echo "Flags can be combined in any order."
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

    local BUILD_TYPE="release"
    if [ "$DEBUG_BUILD_FLAG" = "1" ]; then
        BUILD_TYPE="DEBUG (no license checks)"
    fi

    echo "═══════════════════════════════════════════════════════════"
    echo "  Building bypass_daemon for Android ARM64 (API 34)"
    echo "  Build type: $BUILD_TYPE"
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
        -Wall -Wextra -Wno-unused-parameter
        -DANDROID
        -fPIE
        -fstack-protector-strong
    )

    if [ "$DEBUG_BUILD_FLAG" = "1" ]; then
        CFLAGS+=(
            -DDEBUG_BUILD
            -g -O0
        )
    else
        CFLAGS+=(
            -O2
            # Anti-RE: no frame pointers, no debug info, obfuscate string refs
            -fomit-frame-pointer
            -fvisibility=hidden
            -fdata-sections -ffunction-sections
        )
    fi

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

    local LDFLAGS_EXTRA=()
    if [ "$DEBUG_BUILD_FLAG" != "1" ]; then
        LDFLAGS_EXTRA+=(-Wl,--gc-sections)
    fi

    "$CC" \
        --sysroot="$SYSROOT" \
        -target aarch64-linux-android34 \
        -pie \
        "${LDFLAGS_EXTRA[@]}" \
        "${OBJS[@]}" \
        "$DEPS/lib/libcurl.a" \
        "$DEPS/lib/libssl.a" \
        "$DEPS/lib/libcrypto.a" \
        -lz -ldl \
        -o "$BINARY"

    if [ "$DEBUG_BUILD_FLAG" = "1" ]; then
        echo ""
        echo "[3/3] Skipping strip (debug build)"
    else
        echo ""
        echo "[3/3] Stripping..."
        cp "$BINARY" "$BINARY.debug"
        "$TOOLCHAIN/bin/llvm-objcopy" --strip-all "$BINARY"
    fi

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
DO_COMPILE=0
DO_PACKAGE=0
DEBUG_BUILD_FLAG=0

if [ $# -eq 0 ]; then
    DO_COMPILE=1
fi

for arg in "$@"; do
    case "$arg" in
        --help|-h)   usage ;;
        --clean)     do_clean ;;
        --module)    DO_PACKAGE=1 ;;
        --pack)      DO_COMPILE=1; DO_PACKAGE=1 ;;
        --debug)     DO_COMPILE=1; DEBUG_BUILD_FLAG=1 ;;
        build)       DO_COMPILE=1 ;;
        *)           echo "Unknown option: $arg"; usage ;;
    esac
done

export DEBUG_BUILD_FLAG

if [ "$DO_COMPILE" = "1" ]; then
    do_compile
fi

if [ "$DO_PACKAGE" = "1" ]; then
    do_package
fi
