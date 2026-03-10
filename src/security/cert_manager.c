/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Certificate Manager Implementation (IEC 62351-6)
 *
 * Uses OpenSSL X509 API for certificate loading, public key extraction,
 * and key ID computation.
 */

#include "security/cert_manager.h"

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>

void iec61850_cert_manager_init(iec61850_cert_manager_t *cm)
{
    if (cm != NULL) {
        (void)memset(cm, 0, sizeof(*cm));
    }
}

void iec61850_cert_manager_destroy(iec61850_cert_manager_t *cm)
{
    if (cm == NULL) { return; }

    if (cm->public_key != NULL) {
        EVP_PKEY_free(cm->public_key);
        cm->public_key = NULL;
    }
    if (cm->cert != NULL) {
        X509_free(cm->cert);
        cm->cert = NULL;
    }
    cm->valid = false;
}

/* Compute key ID: first 4 bytes of SHA-1(public key DER) per IEC 62351-6 */
static int compute_key_id(EVP_PKEY *pkey, uint8_t *key_id)
{
    unsigned char *der_buf = NULL;
    int der_len;
    unsigned char sha1_full[20];

    der_len = i2d_PUBKEY(pkey, &der_buf);
    if (der_len <= 0 || der_buf == NULL) {
        return IEC61850_SEC_ERR_PARSE;
    }

    SHA1(der_buf, (size_t)der_len, sha1_full);
    OPENSSL_free(der_buf);

    /* IEC 62351-6: keyID is first 4 bytes of SHA-1 hash */
    memcpy(key_id, sha1_full, IEC61850_CERT_KEYID_LEN);
    return IEC61850_SEC_OK;
}

/* Extract DN string from X509_NAME */
static void extract_dn(X509_NAME *name, char *buf, size_t buf_size)
{
    if (name == NULL) {
        buf[0] = '\0';
        return;
    }
    X509_NAME_oneline(name, buf, (int)buf_size);
    buf[buf_size - 1] = '\0';
}

int iec61850_cert_manager_load(iec61850_cert_manager_t *cm, const char *path)
{
    int result;
    FILE *fp = NULL;

    if (cm == NULL || path == NULL) {
        result = IEC61850_SEC_ERR_ARGS;
        goto done;
    }

    /* Clean up existing */
    iec61850_cert_manager_destroy(cm);
    iec61850_cert_manager_init(cm);

    fp = fopen(path, "rb");
    if (fp == NULL) {
        result = IEC61850_SEC_ERR_FILE;
        goto done;
    }

    /* Try PEM format first */
    cm->cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (cm->cert == NULL) {
        /* Try DER format */
        if (fseek(fp, 0, SEEK_SET) == 0) {
            cm->cert = d2i_X509_fp(fp, NULL);
        }
    }

    if (cm->cert == NULL) {
        result = IEC61850_SEC_ERR_PARSE;
        goto cleanup;
    }

    /* Extract public key (increment reference) */
    cm->public_key = X509_get_pubkey(cm->cert);
    if (cm->public_key == NULL) {
        result = IEC61850_SEC_ERR_PARSE;
        goto cleanup;
    }

    /* Compute key ID (SHA-1 of public key DER) */
    result = compute_key_id(cm->public_key, cm->key_id);
    if (result != IEC61850_SEC_OK) {
        goto cleanup;
    }

    /* Extract subject and issuer DN */
    extract_dn(X509_get_subject_name(cm->cert), cm->subject,
               sizeof(cm->subject));
    extract_dn(X509_get_issuer_name(cm->cert), cm->issuer,
               sizeof(cm->issuer));

    cm->valid = true;
    result = IEC61850_SEC_OK;

cleanup:
    (void)fclose(fp);
done:
    if (result != IEC61850_SEC_OK) {
        iec61850_cert_manager_destroy(cm);
    }
    return result;
}

bool iec61850_cert_manager_is_loaded(const iec61850_cert_manager_t *cm)
{
    return cm != NULL && cm->valid;
}

EVP_PKEY *iec61850_cert_manager_get_public_key(
    const iec61850_cert_manager_t *cm)
{
    if (cm == NULL || !cm->valid) { return NULL; }
    return cm->public_key;
}

const uint8_t *iec61850_cert_manager_get_key_id(
    const iec61850_cert_manager_t *cm)
{
    if (cm == NULL || !cm->valid) { return NULL; }
    return cm->key_id;
}

const char *iec61850_cert_manager_get_subject(
    const iec61850_cert_manager_t *cm)
{
    if (cm == NULL || !cm->valid) { return ""; }
    return cm->subject;
}

const char *iec61850_cert_manager_get_issuer(
    const iec61850_cert_manager_t *cm)
{
    if (cm == NULL || !cm->valid) { return ""; }
    return cm->issuer;
}

/* Load a single CA certificate from PEM or DER file */
static X509 *load_ca_cert(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) { return NULL; }

    X509 *ca = PEM_read_X509(fp, NULL, NULL, NULL);
    if (ca == NULL) {
        if (fseek(fp, 0, SEEK_SET) == 0) {
            ca = d2i_X509_fp(fp, NULL);
        }
    }
    (void)fclose(fp);
    return ca;
}

int iec61850_cert_manager_verify_chain(iec61850_cert_manager_t *cm,
                                         const char *const *ca_paths,
                                         size_t ca_count)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int result = IEC61850_SEC_ERR_VERIFY;

    if (cm == NULL || !cm->valid || ca_paths == NULL || ca_count == 0) {
        return IEC61850_SEC_ERR_ARGS;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        return IEC61850_SEC_ERR_VERIFY;
    }

    /* Load CA certificates into the store */
    for (size_t i = 0; i < ca_count; i++) {
        X509 *ca = load_ca_cert(ca_paths[i]);
        if (ca == NULL) {
            result = IEC61850_SEC_ERR_FILE;
            goto cleanup;
        }
        if (X509_STORE_add_cert(store, ca) != 1) {
            X509_free(ca);
            result = IEC61850_SEC_ERR_VERIFY;
            goto cleanup;
        }
        X509_free(ca);  /* store keeps its own copy */
    }

    /* Create verification context */
    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    if (X509_STORE_CTX_init(ctx, store, cm->cert, NULL) != 1) {
        result = IEC61850_SEC_ERR_VERIFY;
        goto cleanup;
    }

    /* Verify the certificate chain */
    if (X509_verify_cert(ctx) == 1) {
        result = IEC61850_SEC_OK;
    } else {
        result = IEC61850_SEC_ERR_VERIFY;
    }

cleanup:
    if (ctx != NULL) { X509_STORE_CTX_free(ctx); }
    if (store != NULL) { X509_STORE_free(store); }
    return result;
}

bool iec61850_cert_manager_is_valid_time(const iec61850_cert_manager_t *cm)
{
    if (cm == NULL || !cm->valid || cm->cert == NULL) {
        return false;
    }

    /* Check notBefore: cert must be valid now (not in the future) */
    const ASN1_TIME *not_before = X509_get0_notBefore(cm->cert);
    if (not_before != NULL) {
        int day = 0, sec = 0;
        if (ASN1_TIME_diff(&day, &sec, not_before, NULL) == 0) {
            return false;  /* could not compute diff */
        }
        /* If day/sec are negative, current time is before notBefore */
        if (day < 0 || sec < 0) {
            return false;  /* certificate not yet valid */
        }
    }

    /* Check notAfter: cert must not have expired */
    const ASN1_TIME *not_after = X509_get0_notAfter(cm->cert);
    if (not_after != NULL) {
        int day = 0, sec = 0;
        if (ASN1_TIME_diff(&day, &sec, NULL, not_after) == 0) {
            return false;
        }
        /* If day/sec are negative, notAfter is in the past → expired */
        if (day < 0 || sec < 0) {
            return false;  /* certificate expired */
        }
    }

    return true;
}
