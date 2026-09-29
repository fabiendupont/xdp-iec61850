/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Key Manager Implementation (IEC 62351-6)
 *
 * Uses OpenSSL EVP API with goto-cleanup pattern for resource management.
 *
 * License: BSD-3-Clause
 */

#include "security/key_manager.h"

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <string.h>

void iec61850_key_manager_init(iec61850_key_manager_t *km)
{
    if (km != NULL) {
        km->private_key = NULL;
        km->key_type = IEC61850_KEY_UNKNOWN;
    }
}

void iec61850_key_manager_destroy(iec61850_key_manager_t *km)
{
    if (km != NULL) {
        if (km->private_key != NULL) {
            EVP_PKEY_free(km->private_key);
            km->private_key = NULL;
        }
        km->key_type = IEC61850_KEY_UNKNOWN;
    }
}

/* Detect key type from loaded EVP_PKEY */
static void detect_key_type(iec61850_key_manager_t *km)
{
    int key_id;
    int key_bits;

    key_id = EVP_PKEY_id(km->private_key);
    key_bits = EVP_PKEY_bits(km->private_key);

    if (key_id == EVP_PKEY_RSA) {
        if (key_bits == 2048) {
            km->key_type = IEC61850_KEY_RSA_2048;
        } else if (key_bits == 4096) {
            km->key_type = IEC61850_KEY_RSA_4096;
        } else {
            km->key_type = IEC61850_KEY_UNKNOWN;
        }
    } else if (key_id == EVP_PKEY_EC) {
        if (key_bits == 256) {
            km->key_type = IEC61850_KEY_ECDSA_P256;
        } else if (key_bits == 384) {
            km->key_type = IEC61850_KEY_ECDSA_P384;
        } else {
            km->key_type = IEC61850_KEY_UNKNOWN;
        }
    } else {
        km->key_type = IEC61850_KEY_UNKNOWN;
    }
}

int iec61850_key_manager_load_private_key(iec61850_key_manager_t *km,
                                           const char *path, /* NOLINT(bugprone-easily-swappable-parameters) */
                                           const char *passphrase)
{
    int result;
    FILE *fp = NULL;

    if ((km == NULL) || (path == NULL)) {
        result = IEC61850_SEC_ERR_ARGS;
        goto done;
    }

    /* Clean up existing key */
    if (km->private_key != NULL) {
        EVP_PKEY_free(km->private_key);
        km->private_key = NULL;
    }
    km->key_type = IEC61850_KEY_UNKNOWN;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        result = IEC61850_SEC_ERR_FILE;
        goto done;
    }

    /* Try PEM format first */
    km->private_key = PEM_read_PrivateKey(fp, NULL, NULL,
                                           (void *)(uintptr_t)passphrase);
    if (km->private_key == NULL) {
        /* Try DER format */
        if (fseek(fp, 0, SEEK_SET) == 0) {
            km->private_key = d2i_PrivateKey_fp(fp, NULL);
        }
    }

    if (km->private_key == NULL) {
        result = IEC61850_SEC_ERR_PARSE;
        goto cleanup;
    }

    detect_key_type(km);

    if (km->key_type == IEC61850_KEY_UNKNOWN) {
        EVP_PKEY_free(km->private_key);
        km->private_key = NULL;
        result = IEC61850_SEC_ERR_KEY_TYPE;
        goto cleanup;
    }

    result = IEC61850_SEC_OK;

cleanup:
    (void)fclose(fp);
done:
    return result;
}

bool iec61850_key_manager_is_loaded(const iec61850_key_manager_t *km)
{
    if (km == NULL) {
        return false;
    }
    return km->private_key != NULL;
}

iec61850_key_type_t iec61850_key_manager_get_key_type(
    const iec61850_key_manager_t *km)
{
    if (km == NULL) {
        return IEC61850_KEY_UNKNOWN;
    }
    return km->key_type;
}

iec61850_sig_algo_t iec61850_key_manager_get_sig_algo(
    const iec61850_key_manager_t *km)
{
    if (km == NULL) {
        return IEC61850_SIG_RSA_PSS_SHA256;
    }

    switch (km->key_type) {
        case IEC61850_KEY_ECDSA_P256:
        case IEC61850_KEY_ECDSA_P384:
            return IEC61850_SIG_ECDSA_SHA256;
        default:
            return IEC61850_SIG_RSA_PSS_SHA256;
    }
}

size_t iec61850_key_manager_get_sig_size(const iec61850_key_manager_t *km)
{
    if (km == NULL) {
        return 0;
    }

    switch (km->key_type) {
        case IEC61850_KEY_RSA_2048:  return 256;
        case IEC61850_KEY_RSA_4096:  return 512;
        case IEC61850_KEY_ECDSA_P256: return 72;  /* DER-encoded ECDSA */
        case IEC61850_KEY_ECDSA_P384: return 104;
        default:                     return 0;
    }
}

/* Internal: sign with RSA-PSS-SHA256 */
static int sign_rsa_pss(EVP_PKEY *pkey, const uint8_t *data, size_t data_len,
                          uint8_t *sig_out, size_t sig_capacity, size_t *sig_len)
{
    int result;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    size_t required_len = 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        result = IEC61850_SEC_ERR_SIGN;
        goto done;
    }

    if (EVP_DigestSignInit(ctx, &pkey_ctx, EVP_sha256(), NULL, pkey) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if ((EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0)) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &required_len) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if (required_len > sig_capacity) {
        result = IEC61850_SEC_ERR_BUFFER;
        goto cleanup;
    }

    *sig_len = required_len;
    if (EVP_DigestSignFinal(ctx, sig_out, sig_len) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    result = IEC61850_SEC_OK;

cleanup:
    EVP_MD_CTX_free(ctx);
done:
    return result;
}

/* Internal: sign with ECDSA-SHA256 */
static int sign_ecdsa(EVP_PKEY *pkey, const uint8_t *data, size_t data_len,
                        uint8_t *sig_out, size_t sig_capacity, size_t *sig_len)
{
    int result;
    EVP_MD_CTX *ctx = NULL;
    size_t required_len = 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        result = IEC61850_SEC_ERR_SIGN;
        goto done;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &required_len) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    if (required_len > sig_capacity) {
        result = IEC61850_SEC_ERR_BUFFER;
        goto cleanup;
    }

    *sig_len = required_len;
    if (EVP_DigestSignFinal(ctx, sig_out, sig_len) <= 0) {
        result = IEC61850_SEC_ERR_SIGN;
        goto cleanup;
    }

    result = IEC61850_SEC_OK;

cleanup:
    EVP_MD_CTX_free(ctx);
done:
    return result;
}

int iec61850_key_manager_sign(const iec61850_key_manager_t *km,
                               const uint8_t *data, size_t data_len,
                               uint8_t *sig_out, size_t sig_capacity,
                               size_t *sig_len)
{
    if ((km == NULL) || (data == NULL) || (sig_out == NULL) || (sig_len == NULL)) {
        return IEC61850_SEC_ERR_ARGS;
    }
    if (km->private_key == NULL) {
        return IEC61850_SEC_ERR_ARGS;
    }

    switch (km->key_type) {
        case IEC61850_KEY_RSA_2048:
        case IEC61850_KEY_RSA_4096:
            return sign_rsa_pss(km->private_key, data, data_len,
                                sig_out, sig_capacity, sig_len);

        case IEC61850_KEY_ECDSA_P256:
        case IEC61850_KEY_ECDSA_P384:
            return sign_ecdsa(km->private_key, data, data_len,
                              sig_out, sig_capacity, sig_len);

        default:
            return IEC61850_SEC_ERR_KEY_TYPE;
    }
}

/* Internal: verify RSA-PSS */
static int verify_rsa_pss(const uint8_t *data, size_t data_len,
                            const uint8_t *signature, size_t sig_len,
                            EVP_PKEY *public_key)
{
    int result;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto done;
    }

    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, public_key) <= 0) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    if ((EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0)) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(ctx, signature, sig_len) == 1) {
        result = IEC61850_SEC_OK;
    } else {
        result = IEC61850_SEC_ERR_VERIFY;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
done:
    return result;
}

/* Internal: verify ECDSA */
static int verify_ecdsa(const uint8_t *data, size_t data_len,
                          const uint8_t *signature, size_t sig_len,
                          EVP_PKEY *public_key)
{
    int result;
    EVP_MD_CTX *ctx = NULL;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto done;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key) <= 0) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(ctx, signature, sig_len) == 1) {
        result = IEC61850_SEC_OK;
    } else {
        result = IEC61850_SEC_ERR_VERIFY;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
done:
    return result;
}

int iec61850_key_manager_verify(const uint8_t *data, size_t data_len,
                                 const uint8_t *signature, size_t sig_len,
                                 EVP_PKEY *public_key)
{
    int key_id;

    if ((data == NULL) || (signature == NULL) || (public_key == NULL)) {
        return IEC61850_SEC_ERR_ARGS;
    }

    key_id = EVP_PKEY_id(public_key);

    if (key_id == EVP_PKEY_RSA) {
        return verify_rsa_pss(data, data_len, signature, sig_len, public_key);
    } else if (key_id == EVP_PKEY_EC) {
        return verify_ecdsa(data, data_len, signature, sig_len, public_key);
    }

    return IEC61850_SEC_ERR_KEY_TYPE;
}
