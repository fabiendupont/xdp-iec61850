/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — internal sharing contract
 *
 * NOT INSTALLED. Private to src/ied/ln/: each group file
 * (ln_tables_group{1..4}.c) defines its const class array under
 * the name below, explicitly bounded by the group's *_CLASS_COUNT
 * macro; ln_runtime.c aggregates them into the registry it
 * searches for iec61850_ln_class_lookup(). Nothing outside
 * src/ied/ln/ may include this header.
 *
 * The counts are macros (not const objects) so the registry in
 * ln_runtime.c is a fully static-const aggregate — zero runtime
 * initialization. When WP-6c appends classes, bump the macro and
 * the array in the same file; ln_runtime.c needs no changes.
 */

#ifndef IEC61850_LN_SCHEMA_TABLES_H
#define IEC61850_LN_SCHEMA_TABLES_H

#include "ied/ln_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Group 1 — common / substation (ln_tables_group1.c) */
#define LN_GROUP1_CLASS_COUNT 19U
extern const iec61850_ln_class_def_t ln_group1_classes[LN_GROUP1_CLASS_COUNT];

/* Group 2 — protection (ln_tables_group2.c) */
#define LN_GROUP2_CLASS_COUNT 23U
extern const iec61850_ln_class_def_t ln_group2_classes[LN_GROUP2_CLASS_COUNT];

/* Group 3 — measurement / metering / monitoring / supervision
 * (ln_tables_group3.c) */
#define LN_GROUP3_CLASS_COUNT 16U
extern const iec61850_ln_class_def_t ln_group3_classes[LN_GROUP3_CLASS_COUNT];

/* Group 4 — interfacing / archiving / power-related, generic
 * (ln_tables_group4.c) */
#define LN_GROUP4_CLASS_COUNT 5U
extern const iec61850_ln_class_def_t ln_group4_classes[LN_GROUP4_CLASS_COUNT];

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_LN_SCHEMA_TABLES_H */
