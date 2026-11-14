/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN Class Runtime (WP-S6 scaffold)
 *
 * Implemented by WP-6b (ln-schema-pilot) against the frozen
 * interface in include/iec61850/ied/ln_schema.h: class lookup
 * across the group tables, model instantiation via the CDC
 * factories, optional-DO addition.
 */

#include "ied/ln_schema.h"

#include <stddef.h>

const iec61850_ln_class_def_t *iec61850_ln_class_lookup(
    const char *ln_class)
{
    (void)ln_class;
    return NULL; /* implemented by WP-6b */
}

uint32_t iec61850_ln_class_count(void)
{
    return 0U; /* implemented by WP-6b */
}

iec61850_logical_node_t *iec61850_ied_model_add_ln_class(
    iec61850_ied_model_t *model, const char *ld_name,
    const char *ln_class, const char *ln_inst, const char *prefix)
{
    (void)model;
    (void)ld_name;
    (void)ln_class;
    (void)ln_inst;
    (void)prefix;
    return NULL; /* implemented by WP-6b */
}

int iec61850_ln_add_ln_class_do(iec61850_logical_node_t *ln,
                                 const char *ln_class,
                                 const char *do_name)
{
    (void)ln;
    (void)ln_class;
    (void)do_name;
    return -1; /* implemented by WP-6b */
}
