/**
 * safety_monitor.h — Encore profile monitoring and game detection loop
 */

#ifndef ENCORE_SAFETY_MONITOR_H
#define ENCORE_SAFETY_MONITOR_H

#include "common.h"

/**
 * Read the current Encore profile from /data/adb/.config/encore/current_profile.
 * Returns profile ID (0-3) or -1 on error.
 */
int read_current_profile(void);

/**
 * Callback invoked when the Encore profile file changes.
 * Enables bypass charging on PROFILE_PERFORMANCE (1),
 * disables when leaving PROFILE_PERFORMANCE.
 *
 * @param event_type   inotify event type (3 = IN_CLOSE_WRITE)
 * @param filepath     path that changed
 * @param method_index bypass charging method index
 * @param user_data    callback context
 */
int on_profile_change(int event_type, const char *filepath, int method_index, void *user_data);

/**
 * Standalone game monitor loop (when Encore Tweaks is not installed).
 * Polls every 15 seconds, detects foreground games,
 * enables/disables bypass charging accordingly.
 * Does NOT return.
 *
 * @param method_index The bypass charging method to use.
 */
void game_monitor_loop(int method_index);

#endif /* ENCORE_SAFETY_MONITOR_H */
