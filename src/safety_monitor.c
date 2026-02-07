/**
 * safety_monitor.c — Encore profile monitoring and standalone game detection
 *
 * Reconstructed from Ghidra pseudocode:
 *   FUN_0060ceec → read_current_profile()
 *   FUN_0060dc3c → on_profile_change()
 *   FUN_0060cfe0 → game_monitor_loop()
 *
 * Two operating modes:
 *   1. Encore Tweaks mode: Watch the profile file via inotify.
 *      Enable bypass on PROFILE_PERFORMANCE (1), disable otherwise.
 *
 *   2. Standalone mode: Poll every 15 seconds for foreground games.
 *      Enable bypass when a known game is detected, disable on exit.
 *      Also detects MLBB specifically for thread boosting.
 */

#include "safety_monitor.h"
#include "bypass_charging.h"
#include "device_probe.h"
#include "license_manager.h"
#include "logging.h"
#include <signal.h>

/* ─── Known game packages for MLBB detection ───────────────────────── */
static const char *mlbb_packages[] = {
    "com.mobile.legends",
    "com.mobilelegends.hwag",
    "com.mobiin.gp",
    "com.mobilechess.gp",
    NULL,
};

/**
 * Check if a package name is an MLBB variant.
 */
static bool is_mlbb_package(const char *pkg)
{
    for (int i = 0; mlbb_packages[i]; i++) {
        if (strcmp(pkg, mlbb_packages[i]) == 0)
            return true;
    }
    return false;
}

/**
 * read_current_profile — Read the Encore performance profile
 *
 * Reconstructed from FUN_0060ceec:
 *   1. fopen("/data/adb/.config/encore/current_profile", "r")
 *   2. fgets(buf, 0x10)
 *   3. atoi(buf)
 *   4. Validate: must be 0..3, else log error and return -1
 *
 * @return Profile ID (0-3) or -1 on error
 */
int read_current_profile(void)
{
    FILE *f = fopen(PATH_ENCORE_PROFILE, "r");
    if (!f) {
        char *err = strerror(errno);
        log_message(LOG_ERROR, "read_profile: Unable to open current profile: %s", err);
        return -1;
    }

    char buf[16];
    char *ret = fgets(buf, sizeof(buf), f);
    if (!ret) {
        char *err = strerror(errno);
        log_message(LOG_ERROR, "read_profile: Unable to read current profile: %s", err);
        fclose(f);
        return -1;
    }

    fclose(f);

    int profile = atoi(buf);
    if (profile < 0 || profile >= PROFILE_MAX) {
        log_message(LOG_ERROR, "read_profile: Invalid profile value: %d", profile);
        return -1;
    }

    return profile;
}

/**
 * on_profile_change — inotify callback when Encore profile changes
 *
 * Reconstructed from FUN_0060dc3c:
 *   - Only acts on event_type == 3 (IN_CLOSE_WRITE / modify)
 *   - Reads the new profile value
 *   - If profile changed to PERFORMANCE (1): enable bypass charging
 *   - If leaving PERFORMANCE (1): disable bypass charging
 *   - Stores new profile in g_current_profile (mutex-protected)
 *
 * @param event_type    inotify event type
 * @param filepath      path of changed file (unused, always the profile path)
 * @param method_index  bypass charging method index (from user_int)
 * @param user_data     callback context (unused)
 * @return 0 on success
 */
int on_profile_change(int event_type, const char *filepath,
                      int method_index, void *user_data)
{
    (void)filepath;
    (void)user_data;

    /* Only handle CLOSE_WRITE events (event_type 3 in the decompiled code) */
    if (event_type != 3)
        return (int)event_type;  /* pass through other events */

    int new_profile = read_current_profile();
    if (new_profile < 0) {
        log_message(LOG_ERROR, "Invalid profile value in callback: %d", new_profile);
        return new_profile;
    }

    pthread_mutex_lock(&g_profile_mutex);
    int old_profile = g_current_profile;
    pthread_mutex_unlock(&g_profile_mutex);

    if (new_profile == old_profile)
        return 0;  /* No change */

    if (new_profile == PROFILE_PERFORMANCE) {
        log_message(LOG_INFO, "Bypass charging enabled");
        bypass_enable(method_index);
    } else if (old_profile == PROFILE_PERFORMANCE) {
        log_message(LOG_INFO, "Bypass charging disabled");
        bypass_disable(method_index);
    }

    /* Update stored profile */
    pthread_mutex_lock(&g_profile_mutex);
    g_current_profile = new_profile;
    pthread_mutex_unlock(&g_profile_mutex);

    return 0;
}

/**
 * game_monitor_loop — Standalone game detection and bypass charging loop
 *
 * Reconstructed from FUN_0060cfe0:
 *
 * This is an infinite loop that runs when Encore Tweaks is NOT installed.
 * It polls every 15 seconds and:
 *
 *   1. Periodically re-verifies the license (every ~6 hours = 1439 iterations)
 *   2. Detects the foreground app via get_foreground_app()
 *   3. If a game is detected:
 *      a. If it's an MLBB variant:
 *         - Format thread name: "%s.UnityMain" (40 bytes max = 0x28)
 *         - Find thread PID via find_process_pid
 *         - If not found: iVar5=1 (skip enable)
 *         - If found: iVar5=2 (use MLBB thread PID)
 *      b. If NOT MLBB: iVar5=0, g_mlbb_pid=0
 *      c. If iVar5 != 1 && foreground_app != NULL:
 *         - For non-MLBB (iVar5==0): find game PID via find_process_pid
 *         - For MLBB (iVar5==2): use the already-found thread PID
 *         - If PID found: enable bypass charging
 *   4. When the game exits (g_game_pid dies):
 *      a. Disable bypass charging
 *      b. Log "Game exited, bypass charging disabled."
 *
 * State machine:
 *   bVar2 (bypass_active): true when bypass charging is currently enabled
 *   bVar1 (was_active):    previous value of bypass_active
 */
void game_monitor_loop(int method_index)
{
    bool bypass_active = false;
    int license_counter = 0;

    while (1) {
        bool was_active = bypass_active;
        sleep(GAME_POLL_INTERVAL_SEC);

        /* ── License re-verification ──────────────────────────── */
        if (license_counter < LICENSE_RECHECK_ITERS) {
            license_counter++;
        } else {
            int result = check_license(0);
            if (result == LICENSE_CURL_ERROR) {
                if (g_last_curl_error == CURLE_PEER_FAILED_VERIFY_CODE) {
                    log_message(LOG_ERROR,
                                "CURL SSL verification fail (ERROR 60), exiting...");
                    post_notification("CURL SSL verification fail (ERROR 60).");
                    disable_module();
                    exit(1);
                }
                license_counter = 0;  /* Retry on next cycle */
            } else if (result == LICENSE_UNLICENSED) {
                const char *msg = "This device is not licensed to use this module.";
                log_message(LOG_ERROR, "%s", msg);
                post_notification(msg);
                disable_module();
                exit(1);
            } else if (result == LICENSE_DEVICE_ERROR) {
                const char *msg = "Unable to retrieve device information for license verification.";
                log_message(LOG_ERROR, "%s", msg);
                post_notification(msg);
                disable_module();
                exit(1);
            } else {
                license_counter = 0;  /* Reset on success */
            }
        }

        /* ── Foreground app detection ─────────────────────────── */
        if (g_foreground_app == NULL) {
            goto detect_new;
        }

        /* Check if tracked game PID is still alive */
        if (g_game_pid != 0) {
            if (kill(g_game_pid, 0) == -1) {
                g_game_pid = 0;
                free(g_foreground_app);
                g_foreground_app = NULL;
                goto detect_new;
            }
            /* PID still alive, fall through to MLBB/game check */
        }
        goto check_game;

detect_new:
        g_foreground_app = get_foreground_app(
            "/data/adb/.config/encore_addon/bypasschg/game_list");
        if (g_foreground_app == NULL)
            goto no_game;

check_game:
        ;
        /* ── MLBB detection and thread boosting ───────────────── */
        int game_flag;    /* 0=non-MLBB, 1=MLBB-thread-not-found, 2=MLBB-thread-found */
        int found_pid;

        if (is_mlbb_package(g_foreground_app)) {
            if (g_mlbb_pid == 0) {
                /* Format thread name: "%s.UnityMain" (max 0x28 = 40 bytes) */
                char thread_name[40];
                snprintf(thread_name, sizeof(thread_name), "%s%s",
                         g_foreground_app, ".UnityMain");
                g_mlbb_pid = find_process_pid(thread_name);
                if (g_mlbb_pid == 0) {
                    game_flag = 1;   /* Thread not found yet */
                    found_pid = g_mlbb_pid;
                    goto after_mlbb;
                }
                log_message(LOG_INFO, "Boosting MLBB thread %s", thread_name);
            } else {
                if (kill(g_mlbb_pid, 0) != 0) {
                    g_mlbb_pid = 0;
                    /* Re-search */
                    char thread_name[40];
                    snprintf(thread_name, sizeof(thread_name), "%s%s",
                             g_foreground_app, ".UnityMain");
                    g_mlbb_pid = find_process_pid(thread_name);
                    if (g_mlbb_pid == 0) {
                        game_flag = 1;
                        found_pid = g_mlbb_pid;
                        goto after_mlbb;
                    }
                    log_message(LOG_INFO, "Boosting MLBB thread %s", thread_name);
                }
            }
            game_flag = 2;
            found_pid = g_mlbb_pid;
        } else {
            game_flag = 0;
            g_mlbb_pid = 0;
            found_pid = g_mlbb_pid;
        }

after_mlbb:
        g_mlbb_pid = found_pid;

        /* If foreground app is NULL or MLBB thread not found, skip */
        if (g_foreground_app == NULL || game_flag == 1)
            goto no_game;

        /* ── Find game PID ────────────────────────────────────── */
        bypass_active = true;
        if (!was_active) {
            /* For non-MLBB games (game_flag != 2), find the game process PID */
            if (game_flag != 2) {
                found_pid = find_process_pid(g_foreground_app);
            }
            g_game_pid = found_pid;

            bypass_active = false;
            if (found_pid != 0) {
                bypass_enable(method_index);
                log_message(LOG_INFO, "Enable bypass charging for %s...",
                            g_foreground_app);
                bypass_active = true;
            }
        }
        continue;

no_game:
        bypass_active = false;
        if (was_active) {
            bypass_disable(method_index);
            log_message(LOG_INFO, "Game exited, bypass charging disabled.");
            bypass_active = false;
        }
    }
}
