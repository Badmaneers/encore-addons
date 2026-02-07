/**
 * file_io.h — Low-level file I/O helpers
 */

#ifndef ENCORE_FILE_IO_H
#define ENCORE_FILE_IO_H

#include "common.h"

/**
 * Write a formatted string to a file.
 *
 * @param path       File path to write to.
 * @param append     If 1, open in append mode. If 0, truncate.
 * @param use_flock  If 1, use flock(LOCK_EX) during write.
 * @param fmt        printf-style format string.
 * @param ...        Format arguments.
 * @return 0 on success, -1 on failure.
 */
int write_file_formatted(const char *path, int append, int use_flock,
                         const char *fmt, ...);

#endif /* ENCORE_FILE_IO_H */
