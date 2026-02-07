# Android.mk — Build the Encore Bypass Charging Addon for Android
#
# Build with the Android NDK:
#   ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk APP_ABI=arm64-v8a
#
# Or with standalone toolchain:
#   make -f Android.mk
#
# Requires: libcurl and OpenSSL (BoringSSL) for Android

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := bypass_daemon
LOCAL_SRC_FILES := \
    src/main.c \
    src/logging.c \
    src/file_io.c \
    src/device_probe.c \
    src/bypass_charging.c \
    src/license_manager.c \
    src/safety_monitor.c \
    src/file_watcher.c \
    src/crypto_utils.c \
    src/anti_tamper.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS     := -Wall -Wextra -O3 -DANDROID
LOCAL_LDLIBS     := -llog -lpthread
LOCAL_LDFLAGS    := -static

# Link against prebuilt libcurl and libssl/libcrypto if available
# Adjust paths to your prebuilt libraries:
# LOCAL_STATIC_LIBRARIES := curl ssl crypto

include $(BUILD_EXECUTABLE)
