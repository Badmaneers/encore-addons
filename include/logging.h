/**
 * logging.h — Timestamped logging to Encore log file
 */

#ifndef ENCORE_LOGGING_H
#define ENCORE_LOGGING_H

#include "common.h"

/**
 * Log a timestamped message to /data/adb/.config/encore/encore.log.
 *
 * @param level   Log level (LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL).
 * @param fmt     printf-style format string.
 * @param ...     Format arguments.
 */
void log_message(int level, const char *fmt, ...);

/**
 * Print a fatal error in a boxed format to stdout and exit.
 *
 * @param fmt  printf-style format string.
 * @param ...  Format arguments.
 */
void fatal_error(const char *fmt, ...) __attribute__((noreturn));

/**
 * Get the log level name string for display.
 */
const char *log_level_name(int level);

#endif /* ENCORE_LOGGING_H */
