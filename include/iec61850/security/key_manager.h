/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Key Manager for IEC 62351-6 Digital Signatures
 *
 * C11 replacement for C++ KeyManager class. Uses OpenSSL EVP API
 * directly with explicit resource management (no RAII).
 *
 * Supports:
 *   - RSA-PSS-SHA256 (IEC 62351-6 primary algorithm)
 *   - ECDSA-SHA256 (alternative)
 *   - Pre-allocated buffer signing (zero-allocation hot path)
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_KEY_MANAGER_H
#define IEC61850_KEY_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key types */
typedef enum {
    IEC61850_KEY_UNKNOWN   = 0,
    IEC61850_KEY_RSA_2048  = 1,
    IEC61850_KEY_RSA_4096  = 2,
    IEC61850_KEY_ECDSA_P256 = 3,
    IEC61850_KEY_ECDSA_P384 = 4
} iec61850_key_type_t;

/* Signature algorithms (IEC 62351-6) */
typedef enum {
    IEC61850_SIG_RSA_PSS_SHA256 = 0x01,
    IEC61850_SIG_ECDSA_SHA256   = 0x02
} iec61850_sig_algo_t;

/* Error codes */
#define IEC61850_SEC_OK            0
#define IEC61850_SEC_ERR_ARGS     -1
#define IEC61850_SEC_ERR_FILE     -2
#define IEC61850_SEC_ERR_PARSE    -3
#define IEC61850_SEC_ERR_KEY_TYPE -4
#define IEC61850_SEC_ERR_SIGN     -5
#define IEC61850_SEC_ERR_VERIFY   -6
#define IEC61850_SEC_ERR_BUFFER   -7

/* Max signature size (RSA-4096 = 512 bytes) */
#define IEC61850_MAX_SIGNATURE_LEN 512

typedef struct {
    EVP_PKEY *private_key;
    iec61850_key_type_t key_type;
} iec61850_key_manager_t;

/**
 * Initialize key manager.
 */
void iec61850_key_manager_init(iec61850_key_manager_t *km);

/**
 * Destroy key manager and free OpenSSL resources.
 */
void iec61850_key_manager_destroy(iec61850_key_manager_t *km);

/**
 * Load private key from PEM or DER file.
 *
 * @param km         Key manager
 * @param path       Path to private key file
 * @param passphrase Optional passphrase (NULL = no passphrase)
 * @return 0 on success, negative error code on failure
 */
int iec61850_key_manager_load_private_key(iec61850_key_manager_t *km,
                                           const char *path,
                                           const char *passphrase);

/**
 * Check if a private key is loaded.
 */
bool iec61850_key_manager_is_loaded(const iec61850_key_manager_t *km);

/**
 * Get key type.
 */
iec61850_key_type_t iec61850_key_manager_get_key_type(
    const iec61850_key_manager_t *km);

/**
 * Get signature algorithm for loaded key.
 */
iec61850_sig_algo_t iec61850_key_manager_get_sig_algo(
    const iec61850_key_manager_t *km);

/**
 * Get expected signature size for loaded key.
 */
size_t iec61850_key_manager_get_sig_size(const iec61850_key_manager_t *km);

/**
 * Sign data using the loaded private key (pre-allocated buffer).
 *
 * @param km           Key manager
 * @param data         Data to sign
 * @param data_len     Length of data
 * @param sig_out      Output buffer for signature
 * @param sig_capacity Capacity of output buffer
 * @param sig_len      Output: actual signature length
 * @return 0 on success, negative error code on failure
 */
int iec61850_key_manager_sign(const iec61850_key_manager_t *km,
                               const uint8_t *data, size_t data_len,
                               uint8_t *sig_out, size_t sig_capacity,
                               size_t *sig_len);

/**
 * Verify a signature using a public key.
 *
 * @param data       Original data
 * @param data_len   Length of data
 * @param signature  Signature to verify
 * @param sig_len    Length of signature
 * @param public_key Public key (EVP_PKEY, not freed by this function)
 * @return 0 if valid, negative error code if invalid or error
 */
int iec61850_key_manager_verify(const uint8_t *data, size_t data_len,
                                 const uint8_t *signature, size_t sig_len,
                                 EVP_PKEY *public_key);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_KEY_MANAGER_H */
