/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-3 CDC factories — harmonics batch (WP-S6 scaffold)
 *
 * HMV, HWYE, HDEL, SEQ: implemented by WP-6a.
 */

#include "ied/ied_data_model.h"

#include <stddef.h>

iec61850_data_object_t *iec61850_cdc_create_hmv(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}

iec61850_data_object_t *iec61850_cdc_create_hwye(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}

iec61850_data_object_t *iec61850_cdc_create_hdel(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}

iec61850_data_object_t *iec61850_cdc_create_seq(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}
