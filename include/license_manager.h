/**
 * license_manager.h — Device license verification against remote server
 *
 * Security features:
 *   - Challenge-response protocol with server nonces (anti-replay)
 *   - Single-use nonces with 120s lifetime (no legacy fallback)
 *   - Constant-time hash comparison (anti-timing-attack)
 *   - Obfuscated HMAC salt (anti-strings)
 *   - Multiple scattered integrity checks (anti-patching)
 *   - TLS hardening (minimum TLS 1.2, certificate verification)
 */

#ifndef ENCORE_LICENSE_MANAGER_H
#define ENCORE_LICENSE_MANAGER_H

#include "common.h"

/**
 * Perform license verification.
 *
 * @param save_on_fail  If true (1), saves the expected license to /sdcard/ on failure.
 *                      Used on first startup to create the license file.
 *
 * @return LICENSE_OK           (0)  — Device is licensed.
 *         LICENSE_UNLICENSED   (1)  — Device is NOT licensed.
 *         LICENSE_CURL_ERROR   (2)  — Network/curl error (check g_last_curl_error).
 *         LICENSE_TAMPER_ERROR (3)  — Anti-tamper integrity check failed.
 *         LICENSE_NONCE_ERROR  (4)  — Nonce request or validation failed.
 *         LICENSE_DEVICE_ERROR (-1) — Cannot retrieve device info.
 */
int check_license(int save_on_fail);

/**
 * Get the device serial number from /proc/cmdline or system properties.
 * Returns a malloc'd string or NULL on failure.
 */
char *get_device_serial(void);

/**
 * Compute HMAC-SHA256 of a file's contents + obfuscated salt.
 * Matches File_CheckAccess (FUN_0060f7c8) from the original binary.
 * Returns a malloc'd hex string or NULL on failure.
 */
char *compute_file_hmac(const char *filepath);

/**
 * Compute the request signature: SHA256(str1 + str2 + salt).
 * Matches ExecuteNetworkRequest (FUN_0060fa54) from the original binary.
 * Returns a malloc'd hex string or NULL on failure.
 */
char *compute_request_hmac(const char *str1, const char *str2);

/**
 * Compute the nonce-enhanced license response:
 * SHA256(file_hash + serial + salt + nonce)
 * Matches the server's computeNonceResponse().
 * Returns a malloc'd 64-char hex string or NULL on failure.
 */
char *compute_nonce_hmac(const char *file_hash, const char *serial, const char *nonce);

/**
 * Format the license file path: /sdcard/<hash>_license_<serial>
 */
void format_license_path(char *buf, size_t buflen, const char *hash, const char *serial);

/**
 * Format the license verification URL (legacy, no nonce).
 */
void format_license_url(char *buf, size_t buflen, const char *hash, const char *serial);

/**
 * Format the nonce-enabled license verification URL.
 * Appends ?nonce=<nonce> to the standard license URL.
 * This is the preferred protocol for all new server deployments.
 */
void format_nonce_url(char *buf, size_t buflen, const char *hash,
                     const char *serial, const char *nonce);

/**
 * Disable the module by creating the Magisk "disable" flag file.
 * On next reboot, Magisk will skip mounting this module's files.
 */
void disable_module(void);

#endif /* ENCORE_LICENSE_MANAGER_H */
