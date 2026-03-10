/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * HMAC-SHA256 and AES-GMAC Implementation for IEC 62351-6
 *
 * Uses OpenSSL EVP API for cryptographic operations.
 */

#include "security/hmac_verify.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

int hmac_sha256_sign(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out_mac, size_t mac_len)
{
    unsigned int actual_len = 0;
    unsigned char *result;

    if (!key || !data || !out_mac || mac_len < 32) {
        return -2;
    }

    result = HMAC(EVP_sha256(), key, (int)key_len,
                  data, data_len, out_mac, &actual_len);
    if (result == NULL) {
        return -2;
    }

    return 0;
}

int hmac_sha256_verify(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       const uint8_t *expected_mac, size_t mac_len)
{
    uint8_t computed_mac[32];
    int ret;

    if (!key || !data || !expected_mac || mac_len > 32) {
        return -2;
    }

    ret = hmac_sha256_sign(key, key_len, data, data_len,
                           computed_mac, sizeof(computed_mac));
    if (ret != 0) {
        return -2;
    }

    /* Constant-time comparison to prevent timing attacks */
    if (CRYPTO_memcmp(computed_mac, expected_mac, mac_len) != 0) {
        return -1;
    }

    return 0;
}

int aes_gmac_verify(const uint8_t *key, size_t key_len,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *expected_tag, size_t tag_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int ret = -2;
    int outlen = 0;

    if (!key || !iv || !aad || !expected_tag) {
        return -2;
    }

    /* Select cipher based on key length */
    if (key_len == 16) {
        cipher = EVP_aes_128_gcm();
    } else if (key_len == 32) {
        cipher = EVP_aes_256_gcm();
    } else {
        return -2;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -2;
    }

    /* Initialize for decryption (verification) */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    /* Set IV length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             (int)iv_len, NULL) != 1) {
        goto cleanup;
    }

    /* Set key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        goto cleanup;
    }

    /* Provide AAD (GMAC: only AAD, no plaintext) */
    if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) {
        goto cleanup;
    }

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             (int)tag_len,
                             (void *)expected_tag) != 1) {
        goto cleanup;
    }

    /* Finalize — this performs the tag verification */
    if (EVP_DecryptFinal_ex(ctx, NULL, &outlen) > 0) {
        ret = 0;   /* Tag matches */
    } else {
        ret = -1;  /* Tag mismatch */
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
