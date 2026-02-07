/**
 * device_probe.h — Android device information and process detection
 */

#ifndef ENCORE_DEVICE_PROBE_H
#define ENCORE_DEVICE_PROBE_H

#include "common.h"

/**
 * Get the foreground application package name.
 * Uses `dumpsys window visible-apps` with grep filtering.
 * Returns a malloc'd string or NULL if no foreground app detected.
 */
char *get_foreground_app(const char *game_list_path);

/**
 * Find the PID of a process by searching proc cmdline entries.
 * Returns the highest matching PID, or 0 if not found.
 *
 * process_name: The string to search for in cmdline.
 */
int find_process_pid(const char *process_name);

/**
 * Get an Android system property by running `getprop <name>`.
 * Returns a malloc'd string or NULL on failure.
 */
char *get_system_property(const char *prop_name);

/**
 * Execute a shell command and capture stdout.
 * Returns a malloc'd string with first line of output, or NULL on error.
 */
char *execute_command(const char *cmd_fmt, ...);

/**
 * Execute a command via fork+exec with shell as uid 2000.
 * Used for posting notifications and other system interactions.
 * Returns the exit code of the child, or -1 on failure.
 */
int execute_as_shell(const char *cmd_fmt, ...);

/**
 * Post an Android notification via `cmd notification post`.
 *
 * @param message  The notification body text.
 */
void post_notification(const char *message);

/**
 * Check if a PID is still alive via kill(pid, 0).
 */
bool is_pid_alive(int pid);

#endif /* ENCORE_DEVICE_PROBE_H */
