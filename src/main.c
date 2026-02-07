/**
 * main.c — Entry point for the Encore Bypass Charging Addon daemon
 *
 * Reconstructed from Ghidra pseudocode: FUN_0060d2e0
 *
 * Program flow:
 *   1. Check root (uid == 0)
 *   2. If --test: run bypass hardware detection test
 *   3. Otherwise: daemonize, read config, verify license
 *   4. If Encore Tweaks installed: watch profile file for changes
 *   5. Otherwise: run standalone game monitor loop
 *   6. Periodically re-verify license (every 6 hours)
 */

#include "common.h"
#include "bypass_charging.h"
#include "license_manager.h"
#include "device_probe.h"
#include "safety_monitor.h"
#include "logging.h"
#include "file_watcher.h"

/* ─── Global state definitions ─────────────────────────────────────── */
int              g_current_profile   = 0;
pthread_mutex_t  g_profile_mutex     = PTHREAD_MUTEX_INITIALIZER;
char            *g_foreground_app    = NULL;
int              g_game_pid          = 0;
int              g_mlbb_pid          = 0;
int              g_last_curl_error   = 0;
int              g_current_ma_scale  = 0;
char             g_hmac_salt[16]     = {0};
char             g_timestamp_buf[64] = {0};

/**
 * Handle license failure — log, notify, and exit.
 */
static void handle_license_failure(int result)
{
    if (result == LICENSE_CURL_ERROR) {
        if (g_last_curl_error == CURLE_PEER_FAILED_VERIFY_CODE) {
            log_message(LOG_ERROR, "CURL SSL verification fail (ERROR 60), exiting...");
            post_notification("CURL SSL verification fail (ERROR 60).");
            exit(1);
        }
        /* Other curl errors: recoverable, will retry */
        return;
    }

    if (result == LICENSE_UNLICENSED) {
        const char *msg = "This device is not licensed to use this module.";
        log_message(LOG_ERROR, "%s", msg);
        post_notification(msg);
        exit(1);
    }

    if (result == LICENSE_DEVICE_ERROR) {
        const char *msg = "Unable to retrieve device information for license verification.";
        log_message(LOG_ERROR, "%s", msg);
        post_notification(msg);
        exit(1);
    }
}

/**
 * Run the Encore Tweaks integration mode:
 * Watch the profile file and toggle bypass charging on profile 1.
 */
static void run_encore_mode(int method_index)
{
    /* Check Encore version compatibility */
    if (access(PATH_ENCORE_PROFILE, F_OK) != 0) {
        log_message(LOG_FATAL, "Please use Encore Tweaks version 4.5 or newer!");
        post_notification("Please use Encore Tweaks version 4.5 or newer.");
        exit(1);
    }

    /* Wait for profile file to become readable */
    int profile;
    do {
        profile = read_current_profile();
        if (profile == -1) {
            sleep(GAME_POLL_INTERVAL_SEC);
        }
    } while (profile == -1);

    /* Store initial profile */
    pthread_mutex_lock(&g_profile_mutex);
    g_current_profile = profile;
    pthread_mutex_unlock(&g_profile_mutex);

    /* Set up file watcher on the profile file */
    watcher_ctx_t *watcher = watcher_create();
    if (!watcher) {
        log_message(LOG_ERROR, "Failed to create file watcher");
        exit(1);
    }

    if (watcher_add_file(watcher, PATH_ENCORE_PROFILE,
                         method_index, NULL,
                         on_profile_change) != 0) {
        log_message(LOG_ERROR, "Failed to watch profile file");
        watcher_stop(watcher);
        exit(1);
    }

    if (watcher_start(watcher) != 0) {
        log_message(LOG_ERROR, "Watcher start failed");
        watcher_stop(watcher);
        exit(1);
    }

    /* Main loop: periodic license re-verification */
    while (1) {
        sleep(LICENSE_RECHECK_SEC);
        int result = check_license(0);
        if (result == LICENSE_OK) continue;
        handle_license_failure(result);
    }
}

int main(int argc, char *argv[])
{
    /* ── Step 1: Root check ─────────────────────────────────────── */
    if (getuid() != 0) {
        fprintf(stderr, "This program must be run as root (uid 0).\n"
                        "Please run with su or from a root shell.\n");
        exit(1);
    }

    /* ── Step 2: --test mode (bypass charging hardware detection) ── */
    if (argc >= 2 && strcmp(argv[1], "--test") == 0) {
        /* If config already exists, just run the license check */
        if (access(PATH_NODE_CONFIG, F_OK) != 0) {
            run_bypass_test();
            /* run_bypass_test exits on its own */
        }

        /* Config exists — verify license in test mode */
        int result = check_license(1);
        if (result == LICENSE_CURL_ERROR) {
            fatal_error("CURL ERROR %d\nPlease check your internet connection and try again.",
                        g_last_curl_error);
        }
        if (result == LICENSE_UNLICENSED) {
            fatal_error("This device is not licensed to use this module.\n"
                        "If you believe this is a mistake, please contact the maintainer.\n\n"
                        "For more information on licensing and pricing, visit:\n%s",
                        LICENSE_INFO_URL);
        }
        if (result == LICENSE_DEVICE_ERROR) {
            fatal_error("Unable to retrieve device details required for license verification.\n"
                        "Please contact the maintainer for assistance.");
        }
        return 0;
    }

    /* ── Step 3: Daemonize ──────────────────────────────────────── */
    if (daemon(0, 0) != 0) {
        exit(1);
    }

    /* ── Step 4: Read bypass charging config ────────────────────── */
    int method_index = read_node_config();
    if (method_index < 0) {
        exit(1);
    }

    /* ── Step 5: Verify license (with retry on curl errors) ─────── */
    int result;
    do {
        result = check_license(0);
        if (result == LICENSE_CURL_ERROR) {
            if (g_last_curl_error == CURLE_PEER_FAILED_VERIFY_CODE) {
                exit(1);
            }
            sleep(10);
            continue;
        }
        break;
    } while (1);

    if (result == LICENSE_UNLICENSED || result == LICENSE_DEVICE_ERROR) {
        /* First-time failure: retry with save */
        result = check_license(0);
        if (result != LICENSE_OK) {
            handle_license_failure(result);
        }
    }

    /* ── Step 6: Decide operating mode ──────────────────────────── */
    bool encore_installed = (access(PATH_ENCORE_MODULE_PROP, F_OK) == 0) &&
                            (access(PATH_ENCORE_DISABLE, F_OK) != 0);

    if (encore_installed) {
        run_encore_mode(method_index);
    } else {
        game_monitor_loop(method_index);
    }

    return 0;
}
