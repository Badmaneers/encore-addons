/**
 * anti_tamper.c — Anti-tampering, anti-debugging, and integrity checks
 *
 * Multiple layers of protection against reverse engineering and patching:
 *
 * Layer 1: Debugger detection
 *   - ptrace(PTRACE_TRACEME) self-attach check
 *   - /proc/self/status TracerPid parsing
 *   - Detect strace/ltrace/gdb in /proc
 *
 * Layer 2: Framework detection
 *   - Frida (frida-server, frida-agent, libfrida)
 *   - Xposed / LSPosed / EdXposed
 *   - Magisk Hide / Zygisk injector (suspicious libs)
 *
 * Layer 3: Environment checks
 *   - LD_PRELOAD / LD_LIBRARY_PATH hijacking
 *   - Known emulator fingerprints
 *   - /proc/self/maps for injected libraries
 *
 * Layer 4: Booby traps
 *   - Honeypot functions with tempting names
 *   - Delayed-action corruption (don't immediately exit)
 *   - Silent module disable on next reboot
 *
 * Layer 5: Salt obfuscation
 *   - HMAC salt reconstructed at runtime from scattered constants
 *   - Never appears as a contiguous string in the binary
 */

#include "anti_tamper.h"
#include "logging.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>

/* Forward declaration from file_io.c */
extern int write_file_formatted(const char *path, int append, int use_flock,
                                const char *fmt, ...);

/* ─── Internal state ───────────────────────────────────────────────── */
static char s_self_path[256] = {0};
static volatile int s_trap_armed = 0;

/* ─── Obfuscated salt fragments ────────────────────────────────────── */
/* The salt "Watashi...me" is split into scattered pieces with XOR masking.
 * Each fragment is XOR'd with a different key so `strings` cannot find it.
 * The final salt is reconstructed at runtime by at_reconstruct_salt(). */

/* Fragment layout (each byte XOR'd with its index + 0x5A):
 *   W=0x57  a=0x61  t=0x74  a=0x61  s=0x73  h=0x68  i=0x69
 *   .=0x2E  .=0x2E  .=0x2E  m=0x6D  e=0x65
 */
static const unsigned char _sf1[] = { 0x57^0x5A, 0x61^0x5B, 0x74^0x5C, 0x61^0x5D };  /* "Wata" */
static const unsigned char _sf2[] = { 0x73^0x5E, 0x68^0x5F, 0x69^0x60 };              /* "shi" */
static const unsigned char _sf3[] = { 0x2E^0x61, 0x2E^0x62, 0x2E^0x63 };              /* "..." */
static const unsigned char _sf4[] = { 0x6D^0x64, 0x65^0x65 };                          /* "me" */

/**
 * at_reconstruct_salt — Rebuild the HMAC salt from obfuscated fragments.
 */
void at_reconstruct_salt(char *out, size_t outlen)
{
    if (outlen < 13) return;

    int idx = 0;
    for (int i = 0; i < 4; i++)
        out[idx++] = (char)(_sf1[i] ^ (unsigned char)(0x5A + i));
    for (int i = 0; i < 3; i++)
        out[idx++] = (char)(_sf2[i] ^ (unsigned char)(0x5E + i));
    for (int i = 0; i < 3; i++)
        out[idx++] = (char)(_sf3[i] ^ (unsigned char)(0x61 + i));
    for (int i = 0; i < 2; i++)
        out[idx++] = (char)(_sf4[i] ^ (unsigned char)(0x64 + i));
    out[idx] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Initialization
 * ═══════════════════════════════════════════════════════════════════════ */
void at_init(const char *self_path)
{
    if (self_path) {
        strncpy(s_self_path, self_path, sizeof(s_self_path) - 1);
    } else {
        /* Try to resolve own path from /proc/self/exe */
        ssize_t n = readlink("/proc/self/exe", s_self_path, sizeof(s_self_path) - 1);
        if (n > 0) s_self_path[n] = '\0';
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Layer 1: Debugger Detection
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Check TracerPid in /proc/self/status.
 * A nonzero TracerPid means something is tracing us.
 */
static int check_tracer_pid(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return (pid != 0) ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/**
 * Try to ptrace ourselves. If a debugger is already attached, this fails.
 */
static int check_ptrace_self(void)
{
    /* Fork a child that tries to ptrace the parent */
    pid_t child = fork();
    if (child < 0) return 0; /* fork failed, can't check */

    if (child == 0) {
        /* Child: try to attach to parent */
        pid_t parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) != 0) {
            _exit(1);  /* Can't attach = someone else is tracing */
        }
        /* Wait for parent to stop, then detach */
        waitpid(parent, NULL, 0);
        ptrace(PTRACE_DETACH, parent, NULL, NULL);
        _exit(0);
    }

    /* Parent: wait for child result */
    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;  /* Clean — no one else tracing us */
    }
    return 1;  /* Debugger detected */
}

/**
 * Scan /proc for known debugger processes.
 */
static int check_debugger_processes(void)
{
    static const char *debugger_names[] = {
        "gdb", "gdbserver", "lldb", "lldb-server",
        "strace", "ltrace", "frida-server", "ida",
        "radare2", "r2", NULL
    };

    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        /* Only check numeric directories (PIDs) */
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path),
                 "/proc/%s/cmdline", entry->d_name);

        FILE *f = fopen(cmdline_path, "r");
        if (!f) continue;

        char cmdline[256] = {0};
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);

        if (n == 0) continue;

        /* Extract just the binary name (after last /) */
        char *base = strrchr(cmdline, '/');
        base = base ? base + 1 : cmdline;

        for (int i = 0; debugger_names[i]; i++) {
            if (strstr(base, debugger_names[i]) != NULL) {
                closedir(proc);
                return 1;
            }
        }
    }
    closedir(proc);
    return 0;
}

int at_check_debugger(void)
{
    if (check_tracer_pid()) return INTEGRITY_DEBUGGER;
    if (check_ptrace_self()) return INTEGRITY_DEBUGGER;
    if (check_debugger_processes()) return INTEGRITY_DEBUGGER;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Layer 2: Framework Detection
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Check /proc/self/maps for injected libraries (Frida, Xposed, etc.).
 */
static int check_maps_for_frameworks(void)
{
    static const char *suspicious_libs[] = {
        "frida", "libfrida", "frida-agent",
        "xposed", "edxposed", "lsposed",
        "libsubstrate", "substrate",
        "libart_fake", "libgadget",
        "magiskhide",
        NULL
    };

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Convert line to lowercase for case-insensitive matching */
        for (char *p = line; *p; p++) {
            if (*p >= 'A' && *p <= 'Z') *p += 32;
        }

        for (int i = 0; suspicious_libs[i]; i++) {
            if (strstr(line, suspicious_libs[i]) != NULL) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

/**
 * Check for Frida by looking for its default TCP port (27042).
 */
static int check_frida_port(void)
{
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return 0;

    char line[256];
    /* Skip header */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }

    while (fgets(line, sizeof(line), f)) {
        /* Format: sl local_address rem_address ... */
        /* local_address is hex IP:PORT */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        colon = strchr(colon + 1, ':'); /* second colon = port */
        if (!colon) continue;

        unsigned int port = 0;
        if (sscanf(colon + 1, "%X", &port) == 1) {
            /* Frida default: 27042 = 0x69A2 */
            if (port == 0x69A2) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

/**
 * Check for Xposed/LSPosed framework files.
 */
static int check_xposed_files(void)
{
    static const char *xposed_indicators[] = {
        "/data/data/de.robv.android.xposed.installer",
        "/data/data/org.lsposed.manager",
        "/data/data/org.meowcat.edxposed.manager",
        "/data/adb/lspd",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/data/adb/modules/riru_edxposed",
        NULL
    };

    for (int i = 0; xposed_indicators[i]; i++) {
        if (access(xposed_indicators[i], F_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

int at_check_frameworks(void)
{
    if (check_maps_for_frameworks()) return INTEGRITY_FRAMEWORK;
    if (check_frida_port()) return INTEGRITY_FRAMEWORK;
    if (check_xposed_files()) return INTEGRITY_FRAMEWORK;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Layer 3: Environment Checks
 * ═══════════════════════════════════════════════════════════════════════ */
int at_check_environment(void)
{
    /* Check LD_PRELOAD — should not be set for a root daemon */
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && strlen(ld_preload) > 0) {
        return INTEGRITY_ENVIRONMENT;
    }

    /* Check LD_LIBRARY_PATH for suspicious entries */
    const char *ld_path = getenv("LD_LIBRARY_PATH");
    if (ld_path) {
        if (strstr(ld_path, "frida") || strstr(ld_path, "xposed") ||
            strstr(ld_path, "substrate")) {
            return INTEGRITY_ENVIRONMENT;
        }
    }

    /* Check for common emulator indicators */
    static const char *emu_props[] = {
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        NULL
    };
    for (int i = 0; emu_props[i]; i++) {
        if (access(emu_props[i], F_OK) == 0) {
            return INTEGRITY_ENVIRONMENT;
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Layer 4: Booby Traps
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * at_trigger_trap — Silently set the booby trap.
 *
 * Instead of immediately exiting (which would tell the cracker exactly
 * where the check is), we silently arm a trap that:
 *   1. Creates the Magisk disable flag (module won't load next boot)
 *   2. Corrupts the cached license path so recheck will fail
 *   3. Doesn't exit or log — the damage is delayed and silent
 */
void at_trigger_trap(void)
{
    if (s_trap_armed) return;  /* Only arm once */
    s_trap_armed = 1;

    /* Silently create the disable flag */
    FILE *f = fopen(PATH_MODULE_DISABLE, "w");
    if (f) {
        fprintf(f, "1\n");
        fclose(f);
    }

    /* Also create the remove flag — module will be deleted on next reboot */
    f = fopen(PATH_MODULE_REMOVE, "w");
    if (f) {
        fprintf(f, "1\n");
        fclose(f);
    }

    /* Corrupt the node_part config so bypass charging won't work
     * even if someone patches out the disable logic */
    write_file_formatted(PATH_NODE_CONFIG, 0, 0, "-1");
}

/* ─── Honeypot functions ───────────────────────────────────────────── */
/* These are designed to look like easy targets for patching.
 * A cracker looking at symbols will see functions like
 * "bypass_license_check" and try to call them or hook them.
 * Instead of bypassing anything, they arm the booby trap. */

__attribute__((used, visibility("default")))
void bypass_license_check(void)
{
    at_trigger_trap();
}

__attribute__((used, visibility("default")))
void patch_license_return(void)
{
    at_trigger_trap();
}

__attribute__((used, visibility("default")))
void force_license_ok(void)
{
    at_trigger_trap();
}

__attribute__((used, visibility("default")))
void disable_license_verify(void)
{
    at_trigger_trap();
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Nonce Verification
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * at_verify_nonce — Check that a server nonce is fresh.
 *
 * The nonce format is: <timestamp_hex>:<random_hex>
 * We verify the timestamp is within ±120 seconds of current time.
 */
int at_verify_nonce(const char *nonce_hex)
{
    if (!nonce_hex) return 0;

    /* Parse timestamp from nonce (first 8 hex chars = 4 bytes = epoch seconds) */
    const char *colon = strchr(nonce_hex, ':');
    if (!colon || (colon - nonce_hex) < 8) return 0;

    char ts_str[16] = {0};
    strncpy(ts_str, nonce_hex, (size_t)(colon - nonce_hex));

    unsigned long server_time = strtoul(ts_str, NULL, 16);
    unsigned long now = (unsigned long)time(NULL);

    /* Allow ±120 seconds of clock skew */
    long diff = (long)now - (long)server_time;
    if (diff < 0) diff = -diff;

    return (diff <= 120) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Constant-time comparison
 * ═══════════════════════════════════════════════════════════════════════ */
int at_secure_compare(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Full integrity check
 * ═══════════════════════════════════════════════════════════════════════ */
int at_full_integrity_check(void)
{
    int result;

    result = at_check_debugger();
    if (result) {
        at_trigger_trap();
        return result;
    }

    result = at_check_frameworks();
    if (result) {
        at_trigger_trap();
        return result;
    }

    result = at_check_environment();
    if (result) {
        at_trigger_trap();
        return result;
    }

    return 0;
}
