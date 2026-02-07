/**
 * file_watcher.c — inotify-based file watcher for profile monitoring
 *
 * Reconstructed from Ghidra pseudocode:
 *   FUN_0060d2e0 (watcher setup in main) → watcher_create(), watcher_add_file()
 *   FUN_0060de10                         → watcher_thread_func()
 *   FUN_0060ddb4                         → watcher_stop()
 *   FUN_0060e158                         → path_join() helper
 *
 * Architecture:
 *   The watcher uses inotify to monitor a directory for changes to specific files.
 *   It has a dynamic array of "watch entries" (directories), each containing
 *   a dynamic array of "file entries" (specific files within that directory).
 *
 *   Data structure (reconstructed from offset analysis):
 *     watcher_ctx_t:
 *       +0x00: watch_data → watch_list_t*
 *       +0x08: pthread_t
 *       +0x10: thread_result
 *       +0x14: running (uint8_t flag)
 *       +0x18: inotify_fd (int)
 *
 *     watch_list_t: { long count; long capacity; watch_entry_t entries[]; }
 *     watch_entry_t (48 bytes, stride 6*8):
 *       +0x00: file_list_t* files
 *       +0x08: char* dir_path
 *       +0x10: int user_int
 *       +0x18: void* padding
 *       +0x20: void* padding
 *       +0x28: int watch_fd  (inotify watch descriptor, -1 if not yet added)
 *
 *     file_list_t: { long count; long capacity; file_entry_t entries[]; }
 *     file_entry_t (32 bytes, stride 4*8):
 *       +0x00: char* filename
 *       +0x08: int user_int
 *       +0x10: void* user_data
 *       +0x18: callback function pointer
 */

#include "file_watcher.h"
#include "logging.h"
#include <sys/inotify.h>
#include <poll.h>
#include <libgen.h>

/* ─── Internal structures ──────────────────────────────────────────── */

typedef struct file_entry {
    char                  *filename;
    int                    user_int;
    void                  *user_data;
    file_watch_callback_t  callback;
} file_entry_t;

typedef struct file_list {
    long          count;
    long          capacity;
    file_entry_t *entries;
} file_list_t;

typedef struct watch_entry {
    file_list_t *files;
    char        *dir_path;
    int          user_int;       /* unused in this path */
    int          _pad1;
    int          _pad2;
    int          watch_fd;       /* inotify watch descriptor */
} watch_entry_t;

typedef struct watch_list {
    long           count;
    long           capacity;
    watch_entry_t *entries;
} watch_list_t;

/* ─── Helper: join two path components ─────────────────────────────── */
static char *path_join(const char *dir, const char *file)
{
    size_t dlen = strlen(dir);
    size_t flen = strlen(file);
    char *buf = malloc(dlen + flen + 2);
    if (!buf) return NULL;
    sprintf(buf, "%s/%s", dir, file);
    return buf;
}

/* ─── Helper: convert inotify mask to event type ───────────────────── */
static int mask_to_event_type(uint32_t mask)
{
    if (mask & IN_DELETE_SELF)  return 1;
    if (mask & IN_CREATE)      return 2;
    if (mask & IN_CLOSE_WRITE) return 3;
    if (mask & IN_MOVED_FROM)  return 4;
    if (mask & IN_ATTRIB)      return 5;
    if (mask & IN_MOVED_TO)    return 1;
    if (mask & IN_MODIFY)      return 3;
    return 6; /* unknown */
}

/**
 * watcher_create — Allocate a new watcher context
 *
 * Reconstructed from FUN_0060d2e0 watcher setup:
 *   __arg = malloc(0x20)        → watcher_ctx_t (32 bytes)
 *   plVar15 = malloc(400)       → watch_list_t (initial: 400 bytes)
 *   plVar15[0..1] = {0, 50}    → count=0, capacity=50 (from _UNK_001be858)
 *   __arg->watch_data = plVar15->entries
 *   iVar5 = inotify_init1(0x800)  → IN_NONBLOCK
 */
watcher_ctx_t *watcher_create(void)
{
    watcher_ctx_t *ctx = calloc(1, sizeof(watcher_ctx_t));
    if (!ctx) return NULL;

    watch_list_t *wl = calloc(1, sizeof(watch_list_t));
    if (!wl) { free(ctx); return NULL; }

    wl->count = 0;
    wl->capacity = 8;
    wl->entries = calloc(wl->capacity, sizeof(watch_entry_t));
    if (!wl->entries) { free(wl); free(ctx); return NULL; }

    ctx->watch_data = wl;
    ctx->inotify_fd = inotify_init1(IN_NONBLOCK);
    if (ctx->inotify_fd < 0) {
        perror("inotify_init");
        free(wl->entries);
        free(wl);
        free(ctx);
        return NULL;
    }

    return ctx;
}

/**
 * watcher_add_file — Register a file to watch
 *
 * Reconstructed from the path splitting + lookup logic in FUN_0060d2e0:
 *   1. Split filepath into directory + filename
 *   2. Look for existing watch_entry for the directory
 *   3. If not found, create a new one
 *   4. Add a file_entry with the callback
 *   5. Call inotify_add_watch(fd, dir, IN_ALL_EVENTS) if not yet watching
 */
int watcher_add_file(watcher_ctx_t *ctx, const char *filepath,
                     int user_int, void *user_data,
                     file_watch_callback_t callback)
{
    if (!ctx || !filepath || !callback)
        return -1;

    watch_list_t *wl = (watch_list_t *)ctx->watch_data;

    /* Split path into dir + filename */
    char *path_copy = strdup(filepath);
    if (!path_copy) return -1;

    /* Find last '/' */
    char *last_slash = strrchr(path_copy, '/');
    char *dir_part;
    char *file_part;

    if (last_slash) {
        *last_slash = '\0';
        dir_part = path_copy;
        file_part = last_slash + 1;
    } else {
        dir_part = ".";
        file_part = path_copy;
    }

    if (file_part[0] == '\0' || (strlen(file_part) > 0 && file_part[strlen(file_part)-1] == '/')) {
        free(path_copy);
        return -1;
    }

    /* Find or create watch entry for directory */
    watch_entry_t *we = NULL;
    for (long i = 0; i < wl->count; i++) {
        if (strcmp(wl->entries[i].dir_path, dir_part) == 0) {
            we = &wl->entries[i];
            break;
        }
    }

    if (!we) {
        /* Need to add a new watch entry */
        if (wl->count >= wl->capacity) {
            long new_cap = wl->capacity * 2;
            watch_entry_t *new_entries = realloc(wl->entries, new_cap * sizeof(watch_entry_t));
            if (!new_entries) { free(path_copy); return -1; }
            wl->entries = new_entries;
            wl->capacity = new_cap;
        }

        we = &wl->entries[wl->count];
        memset(we, 0, sizeof(*we));
        we->dir_path = strdup(dir_part);
        we->watch_fd = -1;

        file_list_t *fl = calloc(1, sizeof(file_list_t));
        fl->count = 0;
        fl->capacity = 4;
        fl->entries = calloc(fl->capacity, sizeof(file_entry_t));
        we->files = fl;

        wl->count++;
    }

    /* Check if file already registered (error condition in original) */
    file_list_t *fl = we->files;
    for (long i = 0; i < fl->count; i++) {
        if (strcmp(fl->entries[i].filename, file_part) == 0) {
            free(path_copy);
            return -1; /* Already watching this file */
        }
    }

    /* Add file entry */
    if (fl->count >= fl->capacity) {
        long new_cap = fl->capacity * 2;
        file_entry_t *new_entries = realloc(fl->entries, new_cap * sizeof(file_entry_t));
        if (!new_entries) { free(path_copy); return -1; }
        fl->entries = new_entries;
        fl->capacity = new_cap;
    }

    file_entry_t *fe = &fl->entries[fl->count];
    fe->filename = strdup(file_part);
    fe->user_int = user_int;
    fe->user_data = user_data;
    fe->callback = callback;
    fl->count++;

    /* Set up inotify watch if not yet done */
    if (we->watch_fd == -1) {
        we->watch_fd = inotify_add_watch(ctx->inotify_fd, we->dir_path, IN_ALL_EVENTS);
        if (we->watch_fd == -1) {
            perror("inotify_watch_fd");
            free(path_copy);
            return -1;
        }
    }

    free(path_copy);
    return 0;
}

/**
 * watcher_thread_func — Watcher thread main loop
 *
 * Reconstructed from FUN_0060de10:
 *   1. While ctx->running:
 *      a. poll(inotify_fd, timeout=50ms)
 *      b. On readable: read events
 *      c. For each event:
 *         - Match watch descriptor to watch_entry
 *         - Match event name to file_entry (if named event)
 *         - Convert mask to event_type
 *         - Call callback(event_type, full_path, user_int, user_data)
 *   2. On exit: clean up all resources
 */
void *watcher_thread_func(void *arg)
{
    watcher_ctx_t *ctx = (watcher_ctx_t *)arg;
    watch_list_t *wl = (watch_list_t *)ctx->watch_data;

    char event_buf[32768];

    while (ctx->running) {
        struct pollfd pfd = {
            .fd = ctx->inotify_fd,
            .events = POLLIN,
            .revents = 0,
        };

        int ret = poll(&pfd, 1, 50);
        if (ret < 0) {
            perror("poll");
            break;
        }

        if (ret == 0) continue; /* timeout */

        ssize_t len = read(ctx->inotify_fd, event_buf, sizeof(event_buf));
        if (len <= 0) {
            if (len < 0) perror("read");
            continue;
        }

        /* Process events */
        ssize_t offset = 0;
        while (offset < len) {
            struct inotify_event *event = (struct inotify_event *)(event_buf + offset);

            /* Find the matching watch_entry */
            watch_entry_t *we = NULL;
            for (long i = 0; i < wl->count; i++) {
                if (wl->entries[i].watch_fd == event->wd) {
                    we = &wl->entries[i];
                    break;
                }
            }

            if (!we) {
                fprintf(stderr, "MATCHING FILE DESCRIPTOR NOT FOUND! ERROR!\n");
                goto next_event;
            }

            int event_type = mask_to_event_type(event->mask);

            if (event->len > 0) {
                /* Named event — match to file entry */
                file_list_t *fl = we->files;
                file_entry_t *fe = NULL;
                for (long i = 0; i < fl->count; i++) {
                    if (strcmp(fl->entries[i].filename, event->name) == 0) {
                        fe = &fl->entries[i];
                        break;
                    }
                }

                if (fe && event_type != 6) {
                    char *full_path = path_join(we->dir_path, fe->filename);
                    if (full_path) {
                        fe->callback(event_type, full_path, fe->user_int, fe->user_data);
                        free(full_path);
                    }
                }
            } else {
                /* Unnamed event — applies to directory watcher.
                 * Call the first file entry's callback if it exists. */
                file_list_t *fl = we->files;
                if (fl->count > 0 && fl->entries[0].callback && event_type != 6) {
                    fl->entries[0].callback(event_type, we->dir_path,
                                            fl->entries[0].user_int,
                                            fl->entries[0].user_data);
                }
            }

next_event:
            offset += sizeof(struct inotify_event) + event->len;
        }
    }

    /* ── Cleanup ──────────────────────────────────────────────── */
    for (long i = 0; i < wl->count; i++) {
        watch_entry_t *we = &wl->entries[i];

        if (we->files) {
            for (long j = 0; j < we->files->count; j++) {
                free(we->files->entries[j].filename);
            }
            free(we->files->entries);
            free(we->files);
        }

        if (we->watch_fd >= 0)
            inotify_rm_watch(ctx->inotify_fd, we->watch_fd);
        free(we->dir_path);
    }
    free(wl->entries);
    free(wl);

    close(ctx->inotify_fd);
    return NULL;
}

/**
 * watcher_start — Start the watcher thread
 */
int watcher_start(watcher_ctx_t *ctx)
{
    ctx->running = 1;
    int ret = pthread_create(&ctx->thread, NULL, watcher_thread_func, ctx);
    ctx->thread_result = ret;
    if (ret != 0) {
        perror("pthread_create");
        ctx->running = 0;
        return -1;
    }
    return 0;
}

/**
 * watcher_stop — Stop the watcher thread, join, and free context
 *
 * Reconstructed from FUN_0060ddb4:
 *   ctx->running = 0
 *   pthread_join(ctx->thread, &result)
 *   free(ctx)
 */
void watcher_stop(watcher_ctx_t *ctx)
{
    if (!ctx) return;

    ctx->running = 0;
    pthread_join(ctx->thread, NULL);
    free(ctx);
}
