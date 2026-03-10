/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Certificate Manager for IEC 62351-6
 *
 * Loads X.509 certificates (PEM/DER), extracts subject DN,
 * computes key ID (SHA-1 of public key DER), and extracts
 * EVP_PKEY for signature verification.
 */

#ifndef IEC61850_CERT_MANAGER_H
#define IEC61850_CERT_MANAGER_H

#include "security/key_manager.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_CERT_KEYID_LEN    4    /* Key ID per IEC 62351-6 (4 bytes) */
#define IEC61850_CERT_MAX_SUBJECT  256

typedef struct {
    X509 *cert;
    EVP_PKEY *public_key;       /* Extracted from certificate */
    uint8_t key_id[IEC61850_CERT_KEYID_LEN];  /* SHA-1(public key DER) */
    char subject[IEC61850_CERT_MAX_SUBJECT];   /* Subject DN string */
    char issuer[IEC61850_CERT_MAX_SUBJECT];    /* Issuer DN string */
    bool valid;
} iec61850_cert_manager_t;

/**
 * Initialize certificate manager.
 */
void iec61850_cert_manager_init(iec61850_cert_manager_t *cm);

/**
 * Destroy certificate manager and free OpenSSL resources.
 */
void iec61850_cert_manager_destroy(iec61850_cert_manager_t *cm);

/**
 * Load X.509 certificate from PEM or DER file.
 *
 * Extracts public key and computes key ID (SHA-1 of public key DER).
 *
 * @param cm   Certificate manager
 * @param path Path to certificate file
 * @return 0 on success, negative error code on failure
 */
int iec61850_cert_manager_load(iec61850_cert_manager_t *cm, const char *path);

/**
 * Check if a certificate is loaded.
 */
bool iec61850_cert_manager_is_loaded(const iec61850_cert_manager_t *cm);

/**
 * Get the public key for signature verification.
 * The returned pointer is NOT owned by the caller; do NOT free it.
 */
EVP_PKEY *iec61850_cert_manager_get_public_key(
    const iec61850_cert_manager_t *cm);

/**
 * Get the key ID (SHA-1 of public key DER, 20 bytes).
 */
const uint8_t *iec61850_cert_manager_get_key_id(
    const iec61850_cert_manager_t *cm);

/**
 * Get the subject DN string.
 */
const char *iec61850_cert_manager_get_subject(
    const iec61850_cert_manager_t *cm);

/**
 * Get the issuer DN string.
 */
const char *iec61850_cert_manager_get_issuer(
    const iec61850_cert_manager_t *cm);

/**
 * Verify certificate chain against CA certificates.
 *
 * Creates an X509_STORE, loads CA certificates, and verifies the
 * loaded certificate against the chain.
 *
 * @param cm       Certificate manager (must have cert loaded)
 * @param ca_paths Array of paths to CA certificate files (PEM or DER)
 * @param ca_count Number of CA paths
 * @return 0 on success, negative error code on failure
 */
int iec61850_cert_manager_verify_chain(iec61850_cert_manager_t *cm,
                                         const char *const *ca_paths,
                                         size_t ca_count);

/**
 * Check if certificate is currently valid (not expired, not yet valid).
 *
 * @param cm Certificate manager
 * @return true if certificate is within validity period
 */
bool iec61850_cert_manager_is_valid_time(const iec61850_cert_manager_t *cm);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_CERT_MANAGER_H */
