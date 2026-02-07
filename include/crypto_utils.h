/**
 * crypto_utils.h — Cryptographic hash and HMAC operations
 *
 * The original binary statically links both BoringSSL and OpenSSL.
 * This reconstruction uses the OpenSSL EVP API for portability.
 */

#ifndef ENCORE_CRYPTO_UTILS_H
#define ENCORE_CRYPTO_UTILS_H

#include "common.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

/**
 * Compute a SHA-256 digest of the given data.
 * Returns a malloc'd binary digest buffer (caller frees).
 * Sets *out_len to the digest length.
 */
unsigned char *sha256_digest(const void *data, size_t data_len, unsigned int *out_len);

/**
 * Compute an EVP message digest (SHA-256) of a file's contents,
 * appending the salt before finalization.
 * Returns a malloc'd hex string or NULL on failure.
 */
char *sha256_file_with_salt(const char *filepath, const char *salt);

/**
 * Compute HMAC-SHA256(key=<internal>, data=hash+serial+salt).
 * Returns a malloc'd hex string or NULL on failure.
 */
char *hmac_license_signature(const char *file_hash, const char *serial, const char *salt);

/**
 * Convert a binary buffer to a malloc'd hex string.
 * Returns NULL on allocation failure.
 */
char *bin_to_hex(const unsigned char *data, size_t len);

#endif /* ENCORE_CRYPTO_UTILS_H */
