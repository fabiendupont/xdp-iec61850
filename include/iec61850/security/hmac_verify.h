/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * HMAC-SHA256 and AES-GMAC Verification for IEC 62351-6
 *
 * Implements HMAC-SHA256 and AES-GMAC authentication for GOOSE/SV
 * messages per IEC 62351-6:2020. Uses OpenSSL EVP API.
 */

#ifndef IEC61850_HMAC_VERIFY_H
#define IEC61850_HMAC_VERIFY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute HMAC-SHA256 and verify against expected MAC.
 *
 * @param key          HMAC key
 * @param key_len      Key length in bytes
 * @param data         Data to authenticate
 * @param data_len     Data length in bytes
 * @param expected_mac Expected MAC value
 * @param mac_len      MAC length in bytes (typically 32 for SHA-256)
 * @return 0 if MAC matches, -1 on mismatch, -2 on error
 */
int hmac_sha256_verify(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       const uint8_t *expected_mac, size_t mac_len);

/**
 * Compute HMAC-SHA256 signature.
 *
 * @param key      HMAC key
 * @param key_len  Key length in bytes
 * @param data     Data to sign
 * @param data_len Data length in bytes
 * @param out_mac  Output MAC buffer (must be at least 32 bytes)
 * @param mac_len  MAC output length (set to actual length on return)
 * @return 0 on success, negative error code on failure
 */
int hmac_sha256_sign(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out_mac, size_t mac_len);

/**
 * Verify AES-GMAC authentication tag (IEC 62351-6:2020 extended).
 *
 * @param key          AES key (128 or 256 bits)
 * @param key_len      Key length in bytes (16 or 32)
 * @param iv           Initialization vector
 * @param iv_len       IV length in bytes (typically 12)
 * @param aad          Additional authenticated data (the GOOSE/SV PDU)
 * @param aad_len      AAD length in bytes
 * @param expected_tag Expected authentication tag
 * @param tag_len      Tag length in bytes (typically 16)
 * @return 0 if tag matches, -1 on mismatch, -2 on error
 */
int aes_gmac_verify(const uint8_t *key, size_t key_len,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *expected_tag, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_HMAC_VERIFY_H */
