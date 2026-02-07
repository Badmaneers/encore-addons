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
#include "device_probe.h"
#include "logging.h"
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <ctype.h>
#include <sys/stat.h>

/* Forward declaration from file_io.c */
extern int write_file_formatted(const char *path, int append, int use_flock,
                                const char *fmt, ...);

/**
 * HMAC salt used for license verification.
 *
 * Reconstructed from DAT_00681d60 initialization in File_CheckAccess and
 * ExecuteNetworkRequest:
 *   Bytes from s_Watashi_001be428[0..7] = "Watashi."
 *   Then DAT_00681d68 = DAT_001be298 (4 bytes) = "..me" (inferred)
 *   Then DAT_00681d6c = 0x656d = "me" (little-endian)
 *
 * Assembled salt: "Watashi...me" (not NUL-terminated in the 15-byte check)
 * The __strlen_chk(&DAT_00681d60, 0xf) call limits it to 15 bytes max.
 */
static const char HMAC_SALT[] = "Watashi...me";
static const size_t HMAC_SALT_LEN = 12;  /* strlen("Watashi...me") */

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
 */
void format_license_url(char *buf, size_t buflen, const char *hash, const char *serial)
{
    snprintf(buf, buflen, "https://license.rem01gaming.dev/%s/%s", hash, serial);
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
    if (EVP_DigestUpdate(ctx, HMAC_SALT, HMAC_SALT_LEN) != 1) {
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
        EVP_DigestUpdate(ctx, HMAC_SALT, HMAC_SALT_LEN) != 1) {
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
 * check_license — Main license verification
 *
 * Reconstructed from CheckLicense (FUN_0060f114):
 *
 * Flow:
 *   1. Get device serial
 *   2. Find a readable device-unique file and compute its hash
 *   3. Build URL: https://license.rem01gaming.dev/<hash>/<serial>
 *   4. HTTP GET with curl (User-Agent: EncoreLicenseVerifier/1.3, timeout=2, redirect)
 *   5. Store curl error code in g_last_curl_error
 *   6. If curl succeeds:
 *      a. Trim whitespace from response
 *      b. Compare response with expected file hash
 *      c. If match → LICENSE_OK, else → LICENSE_UNLICENSED
 *   7. If curl fails:
 *      a. If error == 0x16 (CURLE_UNSUPPORTED_PROTOCOL) → LICENSE_UNLICENSED
 *      b. Else → LICENSE_CURL_ERROR
 *   8. If save_on_fail and verification failed:
 *      a. Format license path: /sdcard/<hash>_license_<serial>
 *      b. Write expected hash to that path
 *
 * @param save_on_fail  If 1, save expected license data on failure
 * @return LICENSE_OK, LICENSE_UNLICENSED, LICENSE_CURL_ERROR, or LICENSE_DEVICE_ERROR
 */
int check_license(int save_on_fail)
{
    int result;
    char url_buf[256];

    /* Step 1: Get serial */
    char *serial = get_device_serial();
    if (!serial)
        return LICENSE_DEVICE_ERROR;

    /* Step 2: Find device-unique file and compute its salted hash.
     *
     * Original binary (CheckLicense, FUN_0060f114):
     *   Tries up to 6 paths via File_CleanPath("/dev/block/by-name/%s").
     *   Each call formats a different partition name (e.g., "boot", "recovery",
     *   "system", "vendor", "super", "userdata").
     *   For each: stat(path) + File_CheckAccess(path) → HMAC-SHA256.
     *   Final fallback: scaling_available_frequencies.
     */
    static const char *block_partitions[] = {
        "boot", "recovery", "system", "vendor", "super", "userdata", NULL
    };

    char path_buf[256];
    char *file_hash = NULL;
    struct stat st;

    /* Try /dev/block/by-name/<partition> paths first */
    for (int i = 0; block_partitions[i]; i++) {
        snprintf(path_buf, sizeof(path_buf), "/dev/block/by-name/%s",
                 block_partitions[i]);
        if (stat(path_buf, &st) == 0) {
            file_hash = compute_file_hmac(path_buf);
            if (file_hash) break;
        }
    }

    /* Fallback: scaling_available_frequencies */
    if (!file_hash) {
        file_hash = compute_file_hmac(PATH_CPU_FREQ_AVAIL);
    }

    if (!file_hash) {
        free(serial);
        return LICENSE_DEVICE_ERROR;
    }

    /* Step 3: Compute request signature.
     *
     * Original: pcVar6 = ExecuteNetworkRequest(file_hash, serial, file_hash)
     * This concatenates serial + file_hash, appends salt, SHA-256 hashes it.
     */
    char *request_hmac = compute_request_hmac(file_hash, serial);
    if (!request_hmac) {
        free(file_hash);
        free(serial);
        return LICENSE_DEVICE_ERROR;
    }

    /* Step 4: Build verification URL and perform HTTP GET */
    format_license_url(url_buf, sizeof(url_buf), file_hash, serial);

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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    g_last_curl_error = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (g_last_curl_error != CURLE_OK) {
        free(response.data);
        result = (g_last_curl_error != 0x16) ? LICENSE_CURL_ERROR : LICENSE_UNLICENSED;
        goto save_and_cleanup;
    }

    /* Step 5: Validate response */
    if (!response.data) {
        result = LICENSE_CURL_ERROR;
        goto save_and_cleanup;
    }

    trim_response(response.data);

    /* Step 6: Compare server response with the request HMAC.
     *
     * Original (CheckLicense):
     *   sVar9 = strlen(pcVar6);   // pcVar6 = request_hmac
     *   iVar5 = VerifySignature(pcVar6, response_data, sVar9);
     *   if (iVar5 == 0) → success
     *
     * The anti-tamper "whitelisting pattern" with val_acc is obfuscation;
     * at its core: if response matches request_hmac → LICENSE_OK.
     */
    size_t expected_len = strlen(request_hmac);
    if (strlen(response.data) >= expected_len &&
        memcmp(response.data, request_hmac, expected_len) == 0) {
        result = LICENSE_OK;
    } else {
        result = LICENSE_UNLICENSED;
    }

    free(response.data);

save_and_cleanup:
    /* Step 7: On first startup (save_on_fail=1), save license data for reference */
    if (save_on_fail && result != LICENSE_OK) {
        char license_path[256];
        format_license_path(license_path, sizeof(license_path), file_hash, serial);
        write_file_formatted(license_path, 0, 0, "%s", request_hmac);
    }

cleanup:
    free(serial);
    free(file_hash);
    free(request_hmac);
    return result;
}
