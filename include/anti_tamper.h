/**
 * anti_tamper.h — Anti-tampering, anti-debugging, and integrity checks
 *
 * Provides multiple layers of crack protection:
 *   1. Debugger detection (ptrace, TracerPid)
 *   2. Instrumentation framework detection (Frida, Xposed, etc.)
 *   3. Binary self-integrity verification
 *   4. Environment sanity checks
 *   5. Booby trap honeypots
 *   6. Obfuscated salt reconstruction
 */

#ifndef ENCORE_ANTI_TAMPER_H
#define ENCORE_ANTI_TAMPER_H

#include "common.h"

/* ─── Integrity status codes ───────────────────────────────────────── */
#define INTEGRITY_OK          0
#define INTEGRITY_DEBUGGER    1
#define INTEGRITY_FRAMEWORK   2
#define INTEGRITY_BINARY      3
#define INTEGRITY_ENVIRONMENT 4

/**
 * Initialize anti-tamper subsystem.
 * Must be called early in main() before any license checks.
 * Stores the binary's own path for later integrity checks.
 */
void at_init(const char *self_path);

/**
 * Check if a debugger is attached (ptrace / TracerPid / strace / gdb).
 * @return 0 if clean, INTEGRITY_DEBUGGER if debugger detected.
 */
int at_check_debugger(void);

/**
 * Check for known instrumentation frameworks (Frida, Xposed, LSPosed, etc.).
 * @return 0 if clean, INTEGRITY_FRAMEWORK if detected.
 */
int at_check_frameworks(void);

/**
 * Check environment sanity (LD_PRELOAD, emulator indicators, etc.).
 * @return 0 if clean, INTEGRITY_ENVIRONMENT if suspicious.
 */
int at_check_environment(void);

/**
 * Run all integrity checks. On failure, triggers the booby trap
 * (delayed silent corruption) and returns the failure code.
 * @return 0 if all checks pass, nonzero integrity code otherwise.
 */
int at_full_integrity_check(void);

/**
 * Reconstruct the obfuscated HMAC salt at runtime.
 * The salt is never stored as a contiguous string literal in the binary.
 * @param out     Buffer to receive the salt (must be >= 13 bytes).
 * @param outlen  Size of the output buffer.
 */
void at_reconstruct_salt(char *out, size_t outlen);

/**
 * Constant-time memory comparison (wraps CRYPTO_memcmp from OpenSSL).
 * Prevents timing side-channel attacks on hash comparisons.
 * @return 0 if buffers are equal, nonzero otherwise.
 */
int at_secure_compare(const void *a, const void *b, size_t len);

/**
 * Trigger the booby trap — silently corrupt state so the module
 * stops working but doesn't immediately reveal it was detected.
 * The corruption takes effect on the next reboot or license recheck.
 */
void at_trigger_trap(void);

/**
 * Verify the nonce received from the server (timestamp + random).
 * @param nonce_hex  The hex-encoded nonce from the server.
 * @return 1 if the nonce is fresh (within acceptable time window), 0 otherwise.
 */
int at_verify_nonce(const char *nonce_hex);

/* ─── Honeypot functions ───────────────────────────────────────────── */
/* These have obvious names that crackers will call/patch.
 * They silently arm the booby trap instead of doing what they seem to. */
void bypass_license_check(void);
void patch_license_return(void);
void force_license_ok(void);
void disable_license_verify(void);

#endif /* ENCORE_ANTI_TAMPER_H */
