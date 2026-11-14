/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 Logical Node Class Schema
 *
 * Declarative, table-driven LN class definitions: an LN class is a
 * list of (data object name, CDC, mandatory) entries per 7-4. The
 * runtime (src/ied/ln/ln_runtime.c) instantiates LN objects into an
 * IED model through the CDC factories, so LN classes carry no
 * logic — only data.
 *
 * Class tables live in src/ied/ln/ln_tables_group{1..4}.c (one file
 * per 7-4 group; WP-6b implements the pilot set, WP-6c bulk-
 * generates the rest from the owned 7-4 tables).
 *
 * FROZEN INTERFACE (WP-S6). The schema types and function
 * signatures are fixed; table contents are data.
 */

#ifndef IEC61850_LN_SCHEMA_H
#define IEC61850_LN_SCHEMA_H

#include "ied/ied_types.h"
#include "ied/ied_data_model.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One data-object slot in an LN class definition. */
typedef struct {
    const char *do_name;   /* data object name per 7-4 (e.g. "Pos") */
    iec61850_cdc_t cdc;    /* common data class per 7-3 */
    bool mandatory;        /* M per 7-4 (O = optional, both listed) */
} iec61850_ln_do_def_t;

/* One LN class definition (per 7-4). */
typedef struct {
    const char *ln_class;            /* four-letter class name */
    const iec61850_ln_do_def_t *dos; /* DO definitions */
    uint32_t do_count;
} iec61850_ln_class_def_t;

/**
 * Look up an LN class definition by its four-letter name across all
 * compiled group tables. Case-sensitive per 7-4 naming.
 * @return The definition, or NULL when the class is unknown.
 */
const iec61850_ln_class_def_t *iec61850_ln_class_lookup(
    const char *ln_class);

/**
 * Number of compiled class definitions (diagnostics/tests).
 */
uint32_t iec61850_ln_class_count(void);

/**
 * Enumerate compiled class definitions: index 0..count-1.
 * @return The definition at @p index, or NULL when out of range.
 */
const iec61850_ln_class_def_t *iec61850_ln_class_at(uint32_t index);

/**
 * Instantiate an LN of the given class into a logical device.
 *
 * Creates the LN (ld_name/ln_class/ln_inst/prefix per the model
 * API), then every mandatory DO of the class via the CDC factories
 * (optional DOs are skipped). Optional DOs can be added afterwards
 * with iec61850_ln_add_ln_class_do().
 *
 * @param model    The IED model (owns the LD).
 * @param ld_name  Logical device instance name (must exist).
 * @param ln_class Four-letter class name (must compile in).
 * @param ln_inst  LN instance suffix (e.g. "1"; "" for LLN0).
 * @param prefix   LN prefix ("" for none).
 * @return The created LN, or NULL on unknown class/LD, model-full,
 *         or factory failure.
 */
iec61850_logical_node_t *iec61850_ied_model_add_ln_class(
    iec61850_ied_model_t *model, const char *ld_name,
    const char *ln_class, const char *ln_inst, const char *prefix);

/**
 * Add one optional DO (by name) from an LN class definition to an
 * LN previously created with iec61850_ied_model_add_ln_class().
 * @return 0, or -ENOENT when the class or DO name is unknown,
 *         -EEXIST when already present, -ENOMEM on failure.
 */
int iec61850_ln_add_ln_class_do(iec61850_logical_node_t *ln,
                                 const char *ln_class,
                                 const char *do_name);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_LN_SCHEMA_H */
