/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Certificate Provider for IEC 61850
 *
 * WP-S3 scaffold: implemented by WP-3a (cert-provider) against the
 * frozen interface in include/iec61850/security/cert_provider.h.
 */

#include "security/cert_provider.h"

#include <stdlib.h>

iec61850_cert_provider_t *iec61850_cert_provider_create_static(
    const char *cert_path, const char *key_path, const char *trust_path)
{
    (void)cert_path;
    (void)key_path;
    (void)trust_path;
    return NULL; /* implemented by WP-3a */
}

iec61850_cert_provider_t *iec61850_cert_provider_create_spiffe(
    const char *cert_path, const char *key_path, const char *trust_path)
{
    (void)cert_path;
    (void)key_path;
    (void)trust_path;
    return NULL; /* implemented by WP-3a */
}

void iec61850_cert_provider_destroy(iec61850_cert_provider_t *p)
{
    (void)p; /* implemented by WP-3a */
}
