/**
 * file_io.c — Low-level file I/O helpers: sysfs write and formatted write
 *
 * Reconstructed from Ghidra pseudocode:
 *   FUN_0060e94c → write_file_formatted()
 *
 * This function is the core sysfs writer used for:
 *   - Writing enable/disable values to bypass charging sysfs nodes
 *   - Writing log entries to encore.log
 *   - Writing license data to /sdcard/
 *   - Writing node_part config
 */

#include "common.h"
#include <stdarg.h>
#include <sys/file.h>

/**
 * write_file_formatted — Write a formatted string to a file
 *
 * Reconstructed from FUN_0060e94c:
 *   param_1 = file path
 *   param_2 = append flag (bit 0: 1=append/create, 0=truncate/create)
 *   param_3 = flock flag  (bit 0: 1=use flock, 0=no locking)
 *   param_4 = format string
 *   ...     = format args
 *
 * Open flags logic (from decompiled code):
 *   append=1: O_WRONLY|O_CREAT|O_APPEND (0x441)
 *   append=0: O_WRONLY|O_CREAT|O_TRUNC  (0x241)
 *   mode: 0644 (0x1a4)
 *
 * Returns:
 *   0 on success
 *  -1 on failure (null fmt, open failed, write failed, flock failed)
 */
int write_file_formatted(const char *path, int append, int use_flock,
                         const char *fmt, ...)
{
    char buf[1024];
    int fd;
    int flags;
    ssize_t written;
    size_t len;

    if (fmt == NULL)
        return -1;

    /* Format the content */
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* vsnprintf returns the number of chars that would have been written.
     * Original code: if (0xfffffc00 < uVar2 - 0x400) — i.e., if n < 0x400 (1024)
     * meaning it checks the string actually fit. If truncated, treat as error. */
    if (n < 0 || (unsigned int)n >= sizeof(buf))
        return -1;

    len = (size_t)n;

    /* Determine open flags */
    if (append)
        flags = O_WRONLY | O_CREAT | O_APPEND;
    else
        flags = O_WRONLY | O_CREAT | O_TRUNC;

    fd = open(path, flags, 0644);
    if (fd == -1)
        return -1;

    if (use_flock) {
        if (flock(fd, LOCK_EX) == -1) {
            close(fd);
            return -1;
        }
        written = write(fd, buf, len);
        flock(fd, LOCK_UN);
    } else {
        written = write(fd, buf, len);
    }

    close(fd);

    if ((size_t)written != len)
        return -1;

    return 0;
}
