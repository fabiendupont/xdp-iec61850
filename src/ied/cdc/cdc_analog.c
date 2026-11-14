/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-3 CDC factories — analog batch (WP-S6 scaffold)
 *
 * CURS, CSD: implemented by WP-6a.
 */

#include "ied/ied_data_model.h"

#include <stddef.h>

iec61850_data_object_t *iec61850_cdc_create_curs(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}

iec61850_data_object_t *iec61850_cdc_create_csd(const char *name)
{
    (void)name;
    return NULL; /* implemented by WP-6a */
}
