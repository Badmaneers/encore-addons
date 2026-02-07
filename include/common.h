/**
 * common.h — Shared types, constants, and macros for the Encore Bypass Charging Addon
 *
 * Reconstructed from Ghidra pseudocode of the original ARM64 Android binary.
 * Original binary: Encore Bypass Charging Addon v1.3
 * Author attribution: rem01gaming (https://t.me/rem01schannel)
 */

#ifndef ENCORE_COMMON_H
#define ENCORE_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

/* ─── Debug build ──────────────────────────────────────────────────── */
/* When compiled with -DDEBUG_BUILD (via ./build.sh --debug):
 *   - All license checks are bypassed (check_license() returns LICENSE_OK)
 *   - Anti-tamper / anti-debug subsystem is disabled
 *   - Binary is not stripped, includes debug symbols (-g -O0)
 *   - A visible "DEBUG BUILD" banner is printed at startup
 * NEVER ship a debug build to end users. */

/* ─── Version ──────────────────────────────────────────────────────── */
#define ENCORE_ADDON_VERSION        "1.3"
#define ENCORE_USER_AGENT           "EncoreLicenseVerifier/" ENCORE_ADDON_VERSION

/* ─── Paths ────────────────────────────────────────────────────────── */
#define PATH_NODE_CONFIG            "/data/adb/.config/encore_addon/bypasschg/node_part"
#define PATH_ENCORE_MODULE_PROP     "/data/adb/modules/encore/module.prop"
#define PATH_ENCORE_DISABLE         "/data/adb/modules/encore/disable"
#define PATH_ENCORE_PROFILE         "/data/adb/.config/encore/current_profile"
#define PATH_ENCORE_LOG             "/data/adb/.config/encore/encore.log"
#define PATH_BATTERY_CURRENT        "/sys/class/power_supply/battery/current_now"
#define PATH_PROC_CMDLINE           "/proc/cmdline"
#define PATH_CPU_FREQ_AVAIL         "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies"

/* ─── Module paths ─────────────────────────────────────────────────── */
#define PATH_MODULE_DIR             "/data/adb/modules/encore_addon_bypasschg"
#define PATH_MODULE_DISABLE         PATH_MODULE_DIR "/disable"
#define PATH_MODULE_REMOVE          PATH_MODULE_DIR "/remove"

/* ─── License ──────────────────────────────────────────────────────── */
#define LICENSE_BASE_URL            "https://license.rem01gaming.dev"
#define LICENSE_INFO_URL            "https://t.me/rem01schannel/723"
#define LICENSE_PATH_FMT            "/sdcard/%s_license_%s"
#define LICENSE_URL_FMT             LICENSE_BASE_URL "/%s/%s"
/* NOTE: HMAC salt is NO LONGER stored as a plaintext constant.
 * It is reconstructed at runtime from obfuscated fragments in anti_tamper.c.
 * Use at_reconstruct_salt() to obtain the salt. */

/* ─── License retry ────────────────────────────────────────────────── */
#define LICENSE_BOOT_MAX_RETRIES    3     /* Max retries on boot before disabling */
#define LICENSE_BOOT_RETRY_DELAY    15    /* Seconds between retries */

/* ─── License check return codes ───────────────────────────────────── */
#define LICENSE_OK                  0
#define LICENSE_UNLICENSED          1
#define LICENSE_CURL_ERROR          2
#define LICENSE_DEVICE_ERROR        (-1)

/* ─── Curl error codes (subset) ────────────────────────────────────── */
/* These values match the CURLcode enum from curl/curl.h.
 * We define them as plain integers for use in code that does not
 * directly include curl/curl.h (e.g., main.c, safety_monitor.c).
 * When curl/curl.h IS included, it provides these as enum members. */
#define ENCORE_CURLE_OK                    0
#define ENCORE_CURLE_UNSUPPORTED_PROTOCOL  1
#define ENCORE_CURLE_COULDNT_RESOLVE_HOST  6
#define ENCORE_CURLE_SSL_CONNECT_ERROR     35
#define ENCORE_CURLE_PEER_FAILED_VERIFY    60  /* 0x3C — special fatal case */

/* Convenience alias for code that doesn't include curl */
#define CURLE_PEER_FAILED_VERIFY_CODE      60

/* ─── Log levels ───────────────────────────────────────────────────── */
#define LOG_INFO                    1
#define LOG_WARN                    2
#define LOG_ERROR                   3
#define LOG_FATAL                   4

/* ─── Timing constants ─────────────────────────────────────────────── */
#define GAME_POLL_INTERVAL_SEC      15
#define LICENSE_RECHECK_SEC         21600   /* 0x5460 = 6 hours */
#define LICENSE_RECHECK_ITERS       1439    /* 0x59F iterations × 15s ≈ 6 hours */
#define BYPASS_TEST_WAIT_SEC        10
#define BYPASS_TEST_SAMPLES         15
#define BYPASS_TEST_THRESHOLD_MA    80.0f

/* ─── Encore profile IDs ──────────────────────────────────────────── */
#define PROFILE_BALANCED            0
#define PROFILE_PERFORMANCE         1   /* bypass charging enabled */
#define PROFILE_POWERSAVE           2
#define PROFILE_GAMING              3
#define PROFILE_MAX                 4

/* ─── Bypass charging method table ─────────────────────────────────── */
#define MAX_BYPASS_METHODS          49  /* 0x31 */

/**
 * A single sysfs node write operation.
 * Each bypass method may write to multiple sysfs nodes.
 *
 * Original binary struct layout (24 bytes / 3 pointers):
 *   +0x00: char *path          — sysfs path (used for both enable and disable)
 *   +0x08: char *disable_value — value to write when restoring/disabling bypass
 *   +0x10: char *enable_value  — value to write when enabling bypass
 *
 * Enable writes:  entry[+0x10] → entry[+0x00]  (enable_value → path)
 * Disable writes: entry[+0x08] → entry[+0x00]  (disable_value → path)
 */
typedef struct sysfs_node_op {
    const char *path;               /* +0x00  sysfs node path */
    const char *disable_value;      /* +0x08  value to write to disable bypass */
    const char *enable_value;       /* +0x10  value to write to enable bypass */
} sysfs_node_op_t;

/**
 * A bypass charging method descriptor.
 * Each supported vendor/hardware has a named method with N sysfs nodes.
 */
typedef struct bypass_method {
    const char      *name;          /* e.g. "OPLUS_MMI", "TRANSISSION_BYPASSCHG" */
    int              node_count;    /* number of sysfs nodes to write */
    sysfs_node_op_t *nodes;         /* array of node operations */
} bypass_method_t;

/**
 * File watcher context for inotify-based profile monitoring.
 */
typedef struct watcher_ctx {
    void            *watch_data;    /* internal watcher data */
    pthread_t        thread;        /* watcher thread */
    int              thread_result; /* pthread_create result */
    int              inotify_fd;    /* inotify file descriptor */
    volatile uint8_t running;       /* flag: 1=running, 0=stop */
} watcher_ctx_t;

/* ─── Global state ─────────────────────────────────────────────────── */
extern int              g_current_profile;      /* protected by g_profile_mutex */
extern pthread_mutex_t  g_profile_mutex;
extern char            *g_foreground_app;       /* current foreground app package */
extern int              g_game_pid;             /* PID of monitored game process */
extern int              g_mlbb_pid;             /* PID of MLBB game thread */
extern int              g_last_curl_error;      /* last curl error code */
extern int              g_current_ma_scale;     /* 0=raw µA, 1=already mA */
extern char             g_hmac_salt[16];        /* cached HMAC salt string */
extern char             g_timestamp_buf[64];    /* cached timestamp for logging */

#endif /* ENCORE_COMMON_H */
