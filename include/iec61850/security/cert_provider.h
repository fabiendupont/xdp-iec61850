/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Certificate Provider for IEC 61850 (IEC 62351-4 support)
 *
 * Supplies the TLS layer with the local certificate chain, private
 * key, and trust store, with refresh notification so short-lived
 * credentials (e.g. SPIFFE X.509-SVIDs issued by SPIRE) rotate
 * without restart.
 *
 * Two backends (both file-watch based):
 * - static:   conventional long-lived PEM files
 * - spiffe:   PEM files written by a SPIRE-side agent (spiffe-helper
 *             or equivalent); short lifetimes expected, identity is
 *             the SPIFFE URI SAN
 * The backend choice is a policy/documentation distinction at the
 * provider level; the 62351-4 strict profile vs SPIFFE-SVID
 * certificate-policy selection lives in the TLS configuration
 * (transport/tls_socket.h) and is mutually exclusive there.
 *
 * FROZEN INTERFACE (WP-S3). Implementations change; signatures do not.
 */

#ifndef IEC61850_CERT_PROVIDER_H
#define IEC61850_CERT_PROVIDER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iec61850_cert_provider iec61850_cert_provider_t;

struct iec61850_cert_provider {
    /*
     * get(): current credentials. Borrowed PEM pointers, valid until
     * the next refresh() that reports a change (or destroy). Any of
     * the outputs may be NULL/0 when that component is not
     * configured (e.g. no trust store: opportunistic validation).
     * Returns 0, or negative errno.
     */
    int (*get)(iec61850_cert_provider_t *p,
               const char **cert_pem, size_t *cert_len,
               const char **key_pem, size_t *key_len,
               const char **trust_pem, size_t *trust_len);

    /*
     * refresh(): poll for credential changes (file mtime/size watch).
     * Returns 1 when credentials changed since the last call that
     * returned 1, 0 when unchanged, negative errno on error. After a
     * 1 return, get() serves the new values and previously returned
     * pointers are invalid.
     */
    int (*refresh)(iec61850_cert_provider_t *p);

    void (*destroy)(iec61850_cert_provider_t *p);

    void *priv;
};

/**
 * Static PEM backend: conventional long-lived certificate, key, and
 * trust-bundle files, watched for rotation. Any path may be NULL
 * (component not configured). Returns NULL on failure.
 */
iec61850_cert_provider_t *iec61850_cert_provider_create_static(
    const char *cert_path, const char *key_path, const char *trust_path);

/**
 * SPIFFE/SPIRE-compatible backend: PEM files written by a SPIRE-side
 * agent (e.g. spiffe-helper). Same file-watch mechanics; short
 * credential lifetimes and rotation are expected behavior, not
 * errors. Returns NULL on failure.
 */
iec61850_cert_provider_t *iec61850_cert_provider_create_spiffe(
    const char *cert_path, const char *key_path, const char *trust_path);

/**
 * Destroy a provider (any backend).
 */
void iec61850_cert_provider_destroy(iec61850_cert_provider_t *p);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_CERT_PROVIDER_H */
