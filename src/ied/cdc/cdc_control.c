/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-3 CDC factories — control batch (WP-S6 scaffold)
 *
 * APC, ENC, ISC: implemented by WP-6a. Follow the factory pattern in
 * src/ied/ied_data_model.c (do_create + per-CDC DOA trees with the
 * 7-3 attribute names/FCs).
 */

#include "ied/ied_data_model.h"

#include <stddef.h>

iec61850_data_object_t *iec61850_cdc_create_apc(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}

iec61850_data_object_t *iec61850_cdc_create_enc(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}

iec61850_data_object_t *iec61850_cdc_create_isc(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}
