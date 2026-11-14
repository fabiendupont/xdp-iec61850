/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 Model-Driven Publishing Binding
 *
 * WP-S6d scaffold: implemented by WP-6d against the frozen
 * interface in include/iec61850/ied/model_binding.h.
 */

#include "ied/model_binding.h"

#include <errno.h>
#include <stddef.h>

/* Placeholder until WP-6d implements this module. */
typedef int iec61850_model_binding_scaffold_placeholder_t;

int iec61850_model_binding_init(iec61850_model_binding_t *b,
                                 iec61850_ied_model_t *model)
{
    (void)b;
    (void)model;
    return -ENOSYS; /* implemented by WP-6d */
}

int iec61850_model_binding_add_goose(iec61850_model_binding_t *b,
                                      iec61850_goose_publisher_t *pub,
                                      const iec61850_da_ref_t *refs,
                                      uint32_t ref_count)
{
    (void)pub;
    (void)refs;
    (void)ref_count;
    if (b == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-6d */
}

int iec61850_model_binding_add_sv(iec61850_model_binding_t *b,
                                   iec61850_sv_publisher_t *pub,
                                   const iec61850_da_ref_t *refs,
                                   uint32_t ref_count)
{
    (void)pub;
    (void)refs;
    (void)ref_count;
    if (b == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-6d */
}

int iec61850_model_binding_process(iec61850_model_binding_t *b)
{
    (void)b;
    return -ENOSYS; /* implemented by WP-6d */
}

void iec61850_model_binding_destroy(iec61850_model_binding_t *b)
{
    (void)b; /* implemented by WP-6d */
}
