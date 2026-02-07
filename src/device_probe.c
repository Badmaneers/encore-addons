/**
 * device_probe.c — Android device information and process detection
 *
 * Reconstructed from Ghidra pseudocode:
 *   FUN_0060e1f4 → get_foreground_app()
 *   FUN_0060eac8 → find_process_pid()
 *   FUN_0060e408 → get_system_property()    (GetSystemProp)
 *   FUN_0060e658 → execute_as_shell()
 *   FUN_0060ef88 → post_notification()
 *   FUN_0060eeec → format_proc_cmdline_path()  (helper)
 *   FUN_0060f078 → format_game_grep_cmd()       (helper)
 */

#include "device_probe.h"
#include "logging.h"
#include <dirent.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>

/* Forward declaration from file_io.c */
extern int write_file_formatted(const char *path, int append, int use_flock,
                                const char *fmt, ...);

/**
 * get_foreground_app — Detect the foreground application package name
 *
 * Reconstructed from FUN_0060e1f4:
 *   Runs: "dumpsys window visible-apps | grep 'package=.* ' | grep -Eo -f <game_list_path>"
 *   Uses pipe+fork+execle with sh -c
 *   Reads first line of output, strips newline, returns strdup'd result.
 *
 * @param game_list_path  Path to a file containing grep patterns for known games
 * @return malloc'd string with package name, or NULL if not found
 */
char *get_foreground_app(const char *game_list_path)
{
    char cmd[600];
    int pipefd[2];
    pid_t pid;
    char result[256];

    snprintf(cmd, sizeof(cmd),
             "dumpsys window visible-apps | grep 'package=.* ' | grep -Eo -f %s",
             game_list_path);

    if (pipe(pipefd) == -1) {
        log_message(LOG_ERROR, "pipe failed in execute_command()");
        return NULL;
    }

    pid = fork();
    if (pid == 0) {
        /* Child: redirect stdout to pipe write end */
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execle("/system/bin/sh", "sh", "-c", cmd, (char *)NULL,
               (char *[]){ "PATH=/system/bin:/system/xbin:/data/adb/magisk", NULL });
        _exit(127);
    }

    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        log_message(LOG_ERROR, "fork failed in execute_command()");
        return NULL;
    }

    /* Parent: read from pipe read end */
    close(pipefd[1]);

    memset(result, 0, sizeof(result));
    ssize_t total = 0;
    ssize_t n;
    do {
        n = read(pipefd[0], result + total, 255 - total);
        total += n;
        if (n < 1) break;
    } while (total < 255);

    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    /* Check if child exited normally with 0 */
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return NULL;
    }

    /* Strip trailing newline */
    char *nl = strchr(result, '\n');
    if (nl) *nl = '\0';

    if (result[0] == '\0')
        return NULL;

    return strdup(result);
}

/**
 * find_process_pid — Find the PID of a process by name in /proc
 *
 * Reconstructed from FUN_0060eac8:
 *   Iterates /proc/<pid>/cmdline entries, reads contents,
 *   replaces NUL bytes with spaces, then does strstr(cmdline, process_name).
 *   Returns the FIRST matching PID found during iteration.
 *
 * @param process_name  String to search for in /proc/<pid>/cmdline
 * @return Highest matching PID, or 0 if not found
 */
int find_process_pid(const char *process_name)
{
    DIR *proc_dir;
    struct dirent *entry;
    int found_pid = 0;

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir");
        return 0;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR)
            continue;

        /* Check if directory name is all digits (a PID) */
        const char *name = entry->d_name;
        bool is_numeric = true;
        for (const char *p = name; *p; p++) {
            if (*p < '0' || *p > '9') {
                is_numeric = false;
                break;
            }
        }
        if (!is_numeric)
            continue;

        /* Read /proc/<pid>/cmdline */
        char cmdline_path[256];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", name);

        FILE *f = fopen(cmdline_path, "r");
        if (!f) continue;

        char cmdline_buf[4096];
        size_t nread = fread(cmdline_buf, 1, sizeof(cmdline_buf) - 1, f);
        fclose(f);

        if (nread == 0) continue;

        /* Replace NUL bytes with spaces (original does NEON-vectorized NUL→space) */
        for (size_t i = 0; i < nread; i++) {
            if (cmdline_buf[i] == '\0')
                cmdline_buf[i] = ' ';
        }
        cmdline_buf[nread] = '\0';

        /* Search for the process name */
        if (strstr(cmdline_buf, process_name) != NULL) {
            char *endp;
            long pid_val = strtol(name, &endp, 10);
            if (*endp == '\0' && pid_val > 0) {
                /* Original logic: keep the FIRST valid PID found.
                 * If iVar10 != 0 (already have a PID) and new >= existing,
                 * keep the existing one. */
                if (found_pid == 0) {
                    found_pid = (int)pid_val;
                }
            }
        }
    }

    closedir(proc_dir);
    return found_pid;
}

/**
 * get_system_property — Get an Android system property
 *
 * Reconstructed from FUN_0060e408 (GetSystemProp):
 *   fork+exec /system/bin/getprop <prop_name>
 *   Reads output from pipe, strips trailing whitespace and newline.
 *   Returns malloc'd string or NULL.
 */
char *get_system_property(const char *prop_name)
{
    int pipefd[2];
    pid_t pid;
    char result[256];

    if (pipe(pipefd) == -1) {
        log_message(LOG_ERROR, "pipe failed in execute_direct()");
        return NULL;
    }

    pid = fork();
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        char *args[] = { "getprop", (char *)prop_name, NULL };
        execv("/system/bin/getprop", args);
        _exit(127);
    }

    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        log_message(LOG_ERROR, "fork failed in execute_direct()");
        return NULL;
    }

    close(pipefd[1]);

    memset(result, 0, sizeof(result));
    ssize_t total = 0;
    ssize_t n;
    do {
        n = read(pipefd[0], result + total, sizeof(result) - 1 - total);
        total += n;
        if (n < 1) break;
    } while (total < (ssize_t)(sizeof(result) - 1));

    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status)) return NULL;

    /* Strip trailing newline/whitespace */
    while (total > 0 && (result[total-1] == '\n' || result[total-1] == '\r'
                         || result[total-1] == ' '))
        total--;
    result[total] = '\0';

    if (result[0] == '\0') return NULL;

    return strdup(result);
}

/**
 * execute_as_shell — Execute a command as uid 2000 (shell)
 *
 * Reconstructed from FUN_0060e658:
 *   Formats: "su -lp 2000 -c \"<cmd>\" >/dev/null"
 *   fork+execle with /system/bin/sh
 *   Returns child exit code or -1 on failure.
 */
int execute_as_shell(const char *cmd_fmt, ...)
{
    char cmd[600];
    va_list args;
    va_start(args, cmd_fmt);
    vsnprintf(cmd, sizeof(cmd), cmd_fmt, args);
    va_end(args);

    pid_t pid = fork();
    if (pid == 0) {
        execle("/system/bin/sh", "sh", "-c", cmd, (char *)NULL,
               (char *[]){ "PATH=/system/bin:/system/xbin:/data/adb/magisk", NULL });
        _exit(127);
    }

    if (pid == -1) {
        log_message(LOG_ERROR, "fork failed in systemv()");
        return -1;
    }

    int status;
    pid_t ret = waitpid(pid, &status, 0);
    if (ret == -1) return -1;

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    return -1;
}

/**
 * post_notification — Send an Android notification
 *
 * Reconstructed from FUN_0060ef88:
 *   Calls execute_as_shell with:
 *     su -lp 2000 -c "/system/bin/cmd notification post -t 'Encore Bypass Charging' 'BypassChargingAddon' '<message>'" >/dev/null
 *   On failure, logs an error.
 */
void post_notification(const char *message)
{
    int ret = execute_as_shell(
        "su -lp 2000 -c \"/system/bin/cmd notification post -t '%s' '%s' '%s'\" >/dev/null",
        "Encore Bypass Charging", "BypassChargingAddon", message);

    if (ret != 0) {
        log_message(LOG_ERROR, "Unable to post push notification, message: %s", message);
    }
}

/**
 * is_pid_alive — Check if a PID is still running
 * kill(pid, 0) returns 0 if we can signal, or -1 with EPERM if process
 * exists but we lack permission. Either means it's alive.
 */
bool is_pid_alive(int pid)
{
    if (pid <= 0) return false;
    if (kill(pid, 0) == 0) return true;
    return (errno == EPERM);
}
