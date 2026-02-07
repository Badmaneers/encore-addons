/**
 * logging.c — Timestamped logging to Encore log file and console output
 *
 * Reconstructed from Ghidra pseudocode:
 *   FUN_0060e794 → log_message()
 *   FUN_0060ce50 → fatal_error()
 *
 * Writes structured log entries to /data/adb/.config/encore/encore.log
 * Format: "YYYY-MM-DD HH:MM:SS.mmm LEVEL BypassChargingAddon: message"
 */

#include "logging.h"
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

/* ─── Log level names (indexed by LOG_xxx constants) ───────────────── */
static const char *log_level_names[] = {
    [0] = "UNKNOWN",
    [LOG_INFO]  = "INFO",
    [LOG_WARN]  = "WARN",
    [LOG_ERROR] = "ERROR",
    [LOG_FATAL] = "FATAL",
};

static const char *TAG = "BypassChargingAddon";

/* ─── Forward declarations of file-write helper ────────────────────── */
int write_file_formatted(const char *path, int append, int use_flock,
                         const char *fmt, ...);

const char *log_level_name(int level)
{
    if (level >= 0 && level <= LOG_FATAL)
        return log_level_names[level];
    return "UNKNOWN";
}

/**
 * log_message — Timestamped log entry to encore.log
 *
 * Observed behavior from FUN_0060e794:
 *   1. gettimeofday() → localtime() → strftime("%Y-%m-%d %H:%M:%S")
 *   2. Append milliseconds as ".NNN"
 *   3. vsnprintf() the user message
 *   4. Write to log: "[timestamp] [LEVEL] BypassChargingAddon: message\n"
 */
void log_message(int level, const char *fmt, ...)
{
    char timestamp[64];
    char message[256];
    struct timeval tv;
    struct tm *tm_info;

    /* Step 1: Build timestamp */
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    if (tm_info == NULL) {
        snprintf(timestamp, sizeof(timestamp), "[TimeError]");
    } else {
        size_t n = strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        if (n == 0) {
            snprintf(timestamp, sizeof(timestamp), "[TimeFormatError]");
        } else {
            /* Append milliseconds */
            snprintf(timestamp + n, sizeof(timestamp) - n, ".%03ld",
                     tv.tv_usec / 1000);
        }
    }

    /* Step 2: Format the user message */
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    /* Step 3: Write to log file (append mode, with flock) */
    write_file_formatted(PATH_ENCORE_LOG, 1, 1,
                         "%s %s %s: %s\n",
                         timestamp,
                         log_level_name(level),
                         TAG,
                         message);
}

/**
 * fatal_error — Print boxed error to stdout and exit(1)
 *
 * Reconstructed from FUN_0060ce50:
 *   vsnprintf → puts("***...***") → puts(msg) → puts("***...***") → exit(1)
 */
void fatal_error(const char *fmt, ...)
{
    char message[512];

    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    puts("*********************************************************");
    puts(message);
    puts("*********************************************************");
    exit(1);
}
