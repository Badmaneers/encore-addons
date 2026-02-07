/**
 * file_watcher.h — inotify-based file watcher for profile changes
 */

#ifndef ENCORE_FILE_WATCHER_H
#define ENCORE_FILE_WATCHER_H

#include "common.h"

/**
 * Callback type for file change events.
 *
 * @param event_type    Type of event (1=delete, 2=create, 3=modify, 4=move_from, 5=attrib, 6=unknown)
 * @param filepath      Full path of the changed file.
 * @param user_int      Integer context (e.g., method index).
 * @param user_data     Pointer context (e.g., method data).
 * @return 0 on success.
 */
typedef int (*file_watch_callback_t)(int event_type, const char *filepath,
                                     int user_int, void *user_data);

/**
 * Create a new watcher context with inotify.
 * Returns a malloc'd watcher_ctx_t or NULL on failure.
 */
watcher_ctx_t *watcher_create(void);

/**
 * Add a file to watch with the given callback.
 *
 * @param ctx           Watcher context.
 * @param filepath      Full path of the file to watch.
 * @param user_int      Integer to pass to callback (e.g., bypass method index).
 * @param user_data     Pointer to pass to callback.
 * @param callback      Function to call on file changes.
 * @return 0 on success, -1 on failure.
 */
int watcher_add_file(watcher_ctx_t *ctx, const char *filepath,
                     int user_int, void *user_data,
                     file_watch_callback_t callback);

/**
 * Start the watcher thread.
 * The thread polls inotify events and dispatches callbacks.
 * @return 0 on success, -1 on failure.
 */
int watcher_start(watcher_ctx_t *ctx);

/**
 * Stop the watcher thread, clean up resources, and free the context.
 */
void watcher_stop(watcher_ctx_t *ctx);

/**
 * Internal: watcher thread entry point (passed to pthread_create).
 */
void *watcher_thread_func(void *arg);

#endif /* ENCORE_FILE_WATCHER_H */
