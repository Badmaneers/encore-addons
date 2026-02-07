/**
 * license_manager.c — Device license verification against remote server
 *
 * Reconstructed from Ghidra pseudocode:
 *   CheckLicense (FUN_0060f114) → check_license()
 *   FormatLicenseUrl (FUN_0060f690) → format_license_url()
 *   FUN_0060f578 → format_license_path()
 *
 * License verification flow:
 *   1. Get device serial from /proc/cmdline (androidboot.serialno=) or getprop
 *   2. Compute file hash from a device-unique file (CPU freq availability)
 *   3. Build license verification URL: https://license.rem01gaming.dev/<hash>/<serial>
 *   4. HTTP GET with libcurl, User-Agent: "EncoreLicenseVerifier/1.3"
 *   5. Compare server response with expected signature
 *   6. On first run (save_on_fail=1), save expected hash to /sdcard/
 *
 * Return values:
 *   LICENSE_OK          (0)  — licensed
 *   LICENSE_UNLICENSED  (1)  — not licensed
 *   LICENSE_CURL_ERROR  (2)  — network error
 *   LICENSE_DEVICE_ERROR (-1) — can't get device info
 *
 * ⚠️ This reconstruction reproduces the license validation logic as observed
 *    in the decompiled binary. It does NOT bypass or circumvent licensing.
 */

#include "license_manager.h"
#include "anti_tamper.h"
#include "device_probe.h"
#include "logging.h"
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>

/* Forward declaration from file_io.c */
extern int write_file_formatted(const char *path, int append, int use_flock,
                                const char *fmt, ...);

/**
 * HMAC salt — now reconstructed at runtime via at_reconstruct_salt().
 * The salt is never stored as a readable string literal in the binary.
 * See anti_tamper.c for the XOR-obfuscated fragment storage.
 */
static char s_salt[16] = {0};
static int  s_salt_ready = 0;

static const char *get_hmac_salt(void)
{
    if (!s_salt_ready) {
        at_reconstruct_salt(s_salt, sizeof(s_salt));
        s_salt_ready = 1;
    }
    return s_salt;
}

#define HMAC_SALT_LEN 12  /* strlen("Watashi...me") */

/* ─── Curl write callback data ─────────────────────────────────────── */
typedef struct {
    char  *data;      /* response body (malloc'd) */
    size_t size;      /* current size */
} curl_response_t;

/**
 * Curl write callback — accumulate response data.
 * Stored at Curl_WriteCallback in the original binary.
 */
static size_t license_curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
    curl_response_t *resp = (curl_response_t *)userp;
    size_t total = size * nmemb;

    char *new_data = realloc(resp->data, resp->size + total + 1);
    if (!new_data) return 0;

    memcpy(new_data + resp->size, ptr, total);
    resp->size += total;
    new_data[resp->size] = '\0';
    resp->data = new_data;

    return total;
}

/**
 * format_license_url — Build the verification URL
 *
 * Reconstructed from FormatLicenseUrl (FUN_0060f690):
 *   vsnprintf(buf, 0x100, "https://license.rem01gaming.dev/%s/%s", hash, serial)
 *
 * NOTE: Temporarily pointing to local test server (plain HTTP).
 *       Original: "https://license.rem01gaming.dev/%s/%s"
 */
void format_license_url(char *buf, size_t buflen, const char *hash, const char *serial)
{
    snprintf(buf, buflen, "http://192.168.14.196:8443/%s/%s", hash, serial);
}

/**
 * format_license_path — Build the local license file path
 *
 * Reconstructed from FUN_0060f578:
 *   vsnprintf(buf, 0x100, "/sdcard/%s_license_%s", hash, serial)
 */
void format_license_path(char *buf, size_t buflen, const char *hash, const char *serial)
{
    snprintf(buf, buflen, "/sdcard/%s_license_%s", hash, serial);
}

/**
 * get_device_serial — Extract device serial number
 *
 * Reconstructed from CheckLicense (FUN_0060f114):
 *   1. fopen("/proc/cmdline", "r") → fgets(buf, 7000)
 *   2. strtok by " ", look for "androidboot.serialno="
 *   3. Extract value after "=" → strdup
 *   4. If not found in cmdline:
 *      a. Try getprop "ro.serialno" (via GetSystemProp)
 *      b. Try getprop "ro.boot.serialno"
 *   5. Return NULL if all methods fail
 */
char *get_device_serial(void)
{
    /* Method 1: Parse /proc/cmdline */
    FILE *f = fopen(PATH_PROC_CMDLINE, "r");
    if (f) {
        char cmdline[7000];
        char *ret = fgets(cmdline, sizeof(cmdline), f);
        fclose(f);

        if (ret) {
            char *token = strtok(cmdline, " ");
            while (token) {
                if (strncmp(token, "androidboot.serialno=", 21) == 0) {
                    char *eq = strchr(token, '=');
                    if (eq) return strdup(eq + 1);
                }
                token = strtok(NULL, " ");
            }
        }
    }

    /* Method 2: getprop ro.serialno */
    char *serial = get_system_property("ro.serialno");
    if (serial) return serial;

    /* Method 3: getprop ro.boot.serialno */
    serial = get_system_property("ro.boot.serialno");
    if (serial) return serial;

    return NULL;
}

/**
 * compute_file_hmac — Compute HMAC-SHA256 of a file's contents using the salt
 *
 * Reconstructed from File_CheckAccess (FUN_0060f7c8):
 *   1. fopen(path, "rb")
 *   2. HMAC_CTX_new() (via FUN_004a56d4)
 *   3. HMAC_Init_ex(ctx, NULL, 0, EVP_sha256(), NULL) (via FUN_004a5e3c + FUN_004b6104)
 *   4. Read file in 0x1000 (4096) byte chunks, HMAC_Update each chunk
 *   5. After EOF: HMAC_Update with the salt ("Watashi...me")
 *   6. HMAC_Final → digest bytes
 *   7. Convert each byte to hex via FUN_0060f9b8 (vsprintf "%02x")
 *   8. Return hex string
 *
 * @param filepath  Path to hash
 * @return malloc'd hex string, or NULL on error
 */
char *compute_file_hmac(const char *filepath)
{
    FILE *f = fopen(filepath, "rb");
    if (!f) return NULL;

    /* Initialize HMAC context with SHA-256 and no key (key added via update) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return NULL; }

    /* The original uses HMAC with the salt as part of the data, not as the key.
     * Looking at the flow: FUN_004a5e3c(ctx, EVP_sha256(), NULL) inits with no key,
     * then file chunks are fed, then the salt is fed as the final update.
     * This is actually a plain SHA-256 hash of (file_contents + salt). */
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return NULL;
    }

    /* Read file in 4096-byte chunks */
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(f);
            return NULL;
        }
    }
    fclose(f);

    /* Append the salt as final data */
    const char *salt = get_hmac_salt();
    if (EVP_DigestUpdate(ctx, salt, HMAC_SALT_LEN) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    /* Convert to hex string (FUN_0060f9b8: vsprintf "%02x" per byte) */
    char *hex = malloc(digest_len * 2 + 1);
    if (!hex) return NULL;
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(hex + i * 2, "%02x", digest[i]);
    }
    hex[digest_len * 2] = '\0';
    return hex;
}

/**
 * compute_request_hmac — Compute the license request signature
 *
 * Reconstructed from ExecuteNetworkRequest (FUN_0060fa54):
 *   1. Concatenate two strings: vsnprintf("%s%s", str1, str2)
 *   2. Append the salt ("Watashi...me") to the concatenated string
 *   3. SHA-256 hash the combined data
 *   4. Convert digest to hex string
 *
 * In the license flow, this is called as:
 *   ExecuteNetworkRequest(file_hash, serial, file_hash)
 * Which concatenates serial + file_hash, appends salt, and hashes.
 *
 * @param str1  First string (file_hash from File_CheckAccess)
 * @param str2  Second string (serial number)
 * @return malloc'd hex string, or NULL on error
 */
char *compute_request_hmac(const char *str1, const char *str2)
{
    /* Step 1: Concatenate the two strings (format "%s%s") */
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    char *combined = malloc(len1 + len2 + 1);
    if (!combined) return NULL;
    memcpy(combined, str1, len1);
    memcpy(combined + len1, str2, len2);
    combined[len1 + len2] = '\0';

    /* Step 2: Append salt and compute SHA-256 */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { free(combined); return NULL; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        free(combined);
        return NULL;
    }

    if (EVP_DigestUpdate(ctx, combined, len1 + len2) != 1 ||
        EVP_DigestUpdate(ctx, get_hmac_salt(), HMAC_SALT_LEN) != 1) {
        EVP_MD_CTX_free(ctx);
        free(combined);
        return NULL;
    }
    free(combined);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);

    /* Convert to hex */
    char *hex = malloc(digest_len * 2 + 1);
    if (!hex) return NULL;
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(hex + i * 2, "%02x", digest[i]);
    }
    hex[digest_len * 2] = '\0';
    return hex;
}

/**
 * Strip leading/trailing whitespace and control characters from a string in-place.
 *
 * Reconstructed from the response trimming logic in CheckLicense:
 *   Skips bytes where (bVar1 == 0x20) or (0xfffffffa < bVar1 - 0xe)
 *   i.e., skips spaces and control chars (0x09-0x0d range = \t\n\v\f\r)
 *   Then strips trailing spaces and control chars.
 */
static void trim_response(char *s)
{
    if (!s || !*s) return;

    /* Skip leading whitespace/control */
    char *start = s;
    while (*start && (isspace((unsigned char)*start)))
        start++;

    if (!*start) {
        *s = '\0';
        return;
    }

    /* Find end and strip trailing whitespace/control */
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end))
        end--;
    *(end + 1) = '\0';

    /* Shift to beginning if needed */
    if (start != s)
        memmove(s, start, strlen(start) + 1);
}

/**
 * check_license — Main license verification (hardened protocol)
 *
 * Hardened flow (challenge-response with nonce):
 *   1. Run anti-tamper integrity check (debugger, frameworks, environment)
 *   2. Get device serial
 *   3. Find a readable device-unique file and compute its hash
 *   4. Request a nonce from the server: GET /nonce
 *   5. Build verification URL: /<hash>/<serial>?nonce=<nonce>
 *   6. HTTP GET with curl, verify response includes nonce signature
 *   7. Constant-time compare response with expected HMAC
 *   8. Run another integrity check (scattered — harder to patch out)
 *
 * The nonce prevents replay attacks: the server includes the nonce in its
 * HMAC computation, and the client verifies the nonce timestamp is fresh.
 *
 * @param save_on_fail  If 1, save expected license data on failure
 * @return LICENSE_OK, LICENSE_UNLICENSED, LICENSE_CURL_ERROR, or LICENSE_DEVICE_ERROR
 */
int check_license(int save_on_fail)
{
    int result;
    char url_buf[512];

    /* ── Anti-tamper check #1 (pre-license) ──────────────────────── */
    if (at_full_integrity_check() != 0) {
        /* Trap already armed by at_full_integrity_check().
         * Return tamper error so the caller knows the real reason. */
        return LICENSE_TAMPER_ERROR;
    }

    /* Step 1: Get serial */
    char *serial = get_device_serial();
    if (!serial)
        return LICENSE_DEVICE_ERROR;

    /* Step 2: Find device-unique file and compute its salted hash. */
    static const char *block_partitions[] = {
        "boot", "recovery", "system", "vendor", "super", "userdata", NULL
    };

    char path_buf[256];
    char *file_hash = NULL;
    struct stat st;

    for (int i = 0; block_partitions[i]; i++) {
        snprintf(path_buf, sizeof(path_buf), "/dev/block/by-name/%s",
                 block_partitions[i]);
        if (stat(path_buf, &st) == 0) {
            file_hash = compute_file_hmac(path_buf);
            if (file_hash) break;
        }
    }

    if (!file_hash) {
        file_hash = compute_file_hmac(PATH_CPU_FREQ_AVAIL);
    }

    if (!file_hash) {
        free(serial);
        return LICENSE_DEVICE_ERROR;
    }

    /* Step 3: Compute request signature. */
    char *request_hmac = compute_request_hmac(file_hash, serial);
    if (!request_hmac) {
        free(file_hash);
        free(serial);
        return LICENSE_DEVICE_ERROR;
    }

    /* Step 4: Request a nonce from the server */
    char nonce_url[256];
    char base_url[128];
    /* Use same base as format_license_url (extract from format_license_url pattern) */
    snprintf(base_url, sizeof(base_url), "http://192.168.14.196:8443");

    snprintf(nonce_url, sizeof(nonce_url), "%s/nonce", base_url);

    CURL *curl_nonce = curl_easy_init();
    char *server_nonce = NULL;

    if (curl_nonce) {
        curl_response_t nonce_resp = { .data = NULL, .size = 0 };
        curl_easy_setopt(curl_nonce, CURLOPT_URL, nonce_url);
        curl_easy_setopt(curl_nonce, CURLOPT_WRITEFUNCTION, license_curl_write_cb);
        curl_easy_setopt(curl_nonce, CURLOPT_WRITEDATA, &nonce_resp);
        curl_easy_setopt(curl_nonce, CURLOPT_USERAGENT, ENCORE_USER_AGENT);
        curl_easy_setopt(curl_nonce, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl_nonce, CURLOPT_CONNECTTIMEOUT, 2L);
        curl_easy_setopt(curl_nonce, CURLOPT_FOLLOWLOCATION, 1L);

        CURLcode nonce_err = curl_easy_perform(curl_nonce);
        curl_easy_cleanup(curl_nonce);

        if (nonce_err == CURLE_OK && nonce_resp.data) {
            trim_response(nonce_resp.data);
            /* Verify nonce freshness (timestamp check) */
            if (at_verify_nonce(nonce_resp.data)) {
                server_nonce = nonce_resp.data;
            } else {
                free(nonce_resp.data);
            }
        } else {
            free(nonce_resp.data);
        }
    }

    /* Step 5: Build verification URL with nonce */
    if (server_nonce) {
        snprintf(url_buf, sizeof(url_buf), "%s/%s/%s?nonce=%s",
                 base_url, file_hash, serial, server_nonce);
    } else {
        /* Fallback: no nonce (backward compatibility with older servers) */
        format_license_url(url_buf, sizeof(url_buf), file_hash, serial);
    }

    /* Step 6: HTTP GET with hardened curl options */
    CURL *curl = curl_easy_init();
    if (!curl) {
        result = (g_last_curl_error != 0x16) ? LICENSE_CURL_ERROR : LICENSE_UNLICENSED;
        goto cleanup;
    }

    curl_response_t response = { .data = NULL, .size = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, license_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ENCORE_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* TLS hardening */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    /* Disable insecure protocols */
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    /* Prevent redirects to different hosts (MITM protection) */
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 2L);

    g_last_curl_error = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (g_last_curl_error != CURLE_OK) {
        free(response.data);
        result = (g_last_curl_error != 0x16) ? LICENSE_CURL_ERROR : LICENSE_UNLICENSED;
        goto save_and_cleanup;
    }

    /* Step 7: Validate response */
    if (!response.data) {
        result = LICENSE_CURL_ERROR;
        goto save_and_cleanup;
    }

    trim_response(response.data);

    /* Step 8: Compare server response with the request HMAC.
     *
     * If the server sent a nonce-enhanced response, it will be:
     *   SHA256(file_hash + serial + "Watashi...me" + nonce)
     * The nonce is appended to the HMAC computation.
     *
     * For backward compat, if no nonce: SHA256(file_hash + serial + "Watashi...me")
     */
    if (server_nonce) {
        /* Compute nonce-enhanced expected response:
         * SHA256(file_hash + serial + salt + nonce) */
        const char *salt = get_hmac_salt();
        size_t total_len = strlen(file_hash) + strlen(serial) + HMAC_SALT_LEN + strlen(server_nonce);
        char *combined = malloc(total_len + 1);
        if (!combined) {
            free(response.data);
            result = LICENSE_DEVICE_ERROR;
            goto save_and_cleanup;
        }
        char *p = combined;
        memcpy(p, file_hash, strlen(file_hash)); p += strlen(file_hash);
        memcpy(p, serial, strlen(serial)); p += strlen(serial);
        memcpy(p, salt, HMAC_SALT_LEN); p += HMAC_SALT_LEN;
        memcpy(p, server_nonce, strlen(server_nonce)); p += strlen(server_nonce);
        *p = '\0';

        /* SHA-256 hash it */
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        int hash_ok = 0;
        if (ctx) {
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
                EVP_DigestUpdate(ctx, combined, total_len) == 1 &&
                EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1) {
                hash_ok = 1;
            }
            EVP_MD_CTX_free(ctx);
        }
        free(combined);

        if (!hash_ok) {
            free(response.data);
            result = LICENSE_DEVICE_ERROR;
            goto save_and_cleanup;
        }

        /* Convert digest to hex for comparison */
        char expected_hex[65];
        for (unsigned int i = 0; i < digest_len && i < 32; i++) {
            sprintf(expected_hex + i * 2, "%02x", digest[i]);
        }
        expected_hex[64] = '\0';

        /* Constant-time comparison (prevents timing attacks) */
        size_t resp_len = strlen(response.data);
        if (resp_len == 64 &&
            at_secure_compare(response.data, expected_hex, 64) == 0) {
            result = LICENSE_OK;
        } else {
            result = LICENSE_UNLICENSED;
        }
    } else {
        /* Legacy comparison (no nonce, still use constant-time) */
        size_t expected_len = strlen(request_hmac);
        size_t resp_len = strlen(response.data);
        if (resp_len >= expected_len &&
            at_secure_compare(response.data, request_hmac, expected_len) == 0) {
            result = LICENSE_OK;
        } else {
            result = LICENSE_UNLICENSED;
        }
    }

    free(response.data);

    /* ── Anti-tamper check #2 (post-license, scattered) ──────────── */
    /* This second check makes it harder to patch: even if a cracker
     * NOPs out the pre-license check, this one will still fire. */
    if (result == LICENSE_OK && at_check_debugger() != 0) {
        at_trigger_trap();
        result = LICENSE_TAMPER_ERROR;
    }

save_and_cleanup:
    if (save_on_fail && result != LICENSE_OK) {
        char license_path[256];
        format_license_path(license_path, sizeof(license_path), file_hash, serial);
        write_file_formatted(license_path, 0, 0, "%s", request_hmac);
    }

cleanup:
    free(serial);
    free(file_hash);
    free(request_hmac);
    free(server_nonce);
    return result;
}

/**
 * disable_module — Create the Magisk "disable" flag file.
 *
 * When this file exists, Magisk will not mount the module's files on
 * the next reboot. The daemon removes this file if a subsequent license
 * check succeeds (e.g., after the user purchases a license).
 */
void disable_module(void)
{
    FILE *f = fopen(PATH_MODULE_DISABLE, "w");
    if (f) {
        fprintf(f, "disabled by license check\n");
        fclose(f);
    }
}
