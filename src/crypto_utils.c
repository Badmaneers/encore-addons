/**
 * crypto_utils.c — Cryptographic hash and HMAC operations
 *
 * Reconstructed from Ghidra pseudocode:
 *   _INIT_2 (FUN_004d1f0c) → OpenSSL ARM capability probing
 *   ExecuteNetworkRequest  → file hashing (inferred)
 *   VerifySignature        → signature comparison
 *
 * The original binary statically links both BoringSSL and OpenSSL libraries
 * (evidenced by the OPENSSL_armcap env check in _INIT_2 and extensive
 * crypto function bodies in the 0x32xxxx-0x60xxxx range).
 *
 * For this reconstruction, we use the standard OpenSSL EVP API.
 *
 * CONFIDENCE:
 *   - SHA-256 usage: HIGH (EVP/digest infrastructure is present)
 *   - HMAC usage: MEDIUM (inferred from VerifySignature pattern)
 *   - Exact key/salt: LOW (partially obfuscated in binary)
 */

#include "crypto_utils.h"

/**
 * sha256_digest — Compute SHA-256 of raw data
 */
unsigned char *sha256_digest(const void *data, size_t data_len, unsigned int *out_len)
{
    unsigned char *digest = malloc(EVP_MAX_MD_SIZE);
    if (!digest) return NULL;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { free(digest); return NULL; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    return digest;
}

/**
 * bin_to_hex — Convert binary data to hex string
 */
char *bin_to_hex(const unsigned char *data, size_t len)
{
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;

    for (size_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", data[i]);

    hex[len * 2] = '\0';
    return hex;
}

/**
 * sha256_file_with_salt — Compute SHA-256(file_contents + salt)
 *
 * This is the inferred implementation of the file hashing step in CheckLicense.
 * The original calls ExecuteNetworkRequest(file_access_result, serial, file_access_result)
 * which likely reads the file and computes a salted hash.
 */
char *sha256_file_with_salt(const char *filepath, const char *salt)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return NULL;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return NULL; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return NULL;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(ctx, buf, n);
    }
    fclose(f);

    /* Append salt */
    if (salt) {
        EVP_DigestUpdate(ctx, salt, strlen(salt));
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    return bin_to_hex(digest, digest_len);
}

/**
 * hmac_license_signature — Compute HMAC-SHA256 for license validation
 *
 * CONFIDENCE: MEDIUM
 * The exact HMAC key is obfuscated in the binary.
 * The VerifySignature function at the end of CheckLicense appears to do
 * a constant-time comparison of the server response against a locally
 * computed value. The anti-tamper "val_acc" pattern wraps this check.
 */
char *hmac_license_signature(const char *file_hash, const char *serial, const char *salt)
{
    /* Build message: hash + serial */
    size_t msg_len = strlen(file_hash) + strlen(serial) + 1;
    char *msg = malloc(msg_len + 1);
    if (!msg) return NULL;
    snprintf(msg, msg_len + 1, "%s%s", file_hash, serial);

    unsigned int hmac_len = 0;
    unsigned char *hmac_result = HMAC(EVP_sha256(),
                                      salt, (int)strlen(salt),
                                      (unsigned char *)msg, strlen(msg),
                                      NULL, &hmac_len);
    free(msg);

    if (!hmac_result || hmac_len == 0) return NULL;

    return bin_to_hex(hmac_result, hmac_len);
}
