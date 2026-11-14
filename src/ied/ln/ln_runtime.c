/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN Class Runtime (WP-6b)
 *
 * Implements the frozen interface in include/iec61850/ied/ln_schema.h
 * against the group tables in ln_tables_group{1..4}.c (shared via
 * ln_schema_tables.h, internal to src/ied/ln/):
 *
 *  - lookup across all compiled group tables,
 *  - model instantiation: the LN plus every MANDATORY DO of its
 *    class through the CDC factory dispatch below,
 *  - optional-DO addition by name.
 *
 * The tables are const data; this runtime carries no per-class
 * logic (WP-6c bulk-generates further tables without touching it).
 */

#include "ln_schema_tables.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ========================================================================
 * Group-table registry
 * ======================================================================== */

/* One compiled group table (see ln_schema_tables.h). */
typedef struct {
    const iec61850_ln_class_def_t *classes;
    uint32_t count;
} ln_group_table_t;

/* Aggregate registry: every compiled 7-4 group, in group order.
 * Counts come from the LN_GROUP*_CLASS_COUNT macros so the
 * registry is a fully static-const aggregate. */
static const ln_group_table_t ln_groups[] = {
    { ln_group1_classes, LN_GROUP1_CLASS_COUNT },
    { ln_group2_classes, LN_GROUP2_CLASS_COUNT },
    { ln_group3_classes, LN_GROUP3_CLASS_COUNT },
    { ln_group4_classes, LN_GROUP4_CLASS_COUNT },
};

#define LN_GROUP_COUNT (sizeof(ln_groups) / sizeof(ln_groups[0]))

const iec61850_ln_class_def_t *iec61850_ln_class_lookup(
    const char *ln_class)
{
    if (ln_class == NULL) {
        return NULL;
    }

    for (size_t g = 0U; g < LN_GROUP_COUNT; g++) {
        for (uint32_t i = 0U; i < ln_groups[g].count; i++) {
            const iec61850_ln_class_def_t *def = &ln_groups[g].classes[i];
            /* NULL guard: a group array shorter than its bound is
             * zero-filled, and such tail slots must never match. */
            if ((def->ln_class != NULL) &&
                (strcmp(def->ln_class, ln_class) == 0)) {
                return def;
            }
        }
    }
    return NULL;
}

uint32_t iec61850_ln_class_count(void)
{
    uint32_t total = 0U;

    for (size_t g = 0U; g < LN_GROUP_COUNT; g++) {
        total += ln_groups[g].count;
    }
    return total;
}

/* ========================================================================
 * CDC factory dispatch
 * ======================================================================== */

/*
 * Map a CDC to its factory in src/ied/ied_data_model.c. There is no
 * pre-existing cdc->factory switch in the tree (callers invoke the
 * factories directly), so the runtime owns this dispatch. It covers
 * the 24 implemented CDCs; the WP-S6 stubs (APC/ENC/ISC/CURS/CSD/
 * SEQ/HMV/HWYE/HDEL) and any unknown value fall through to NULL,
 * failing the instantiation per the WP-S6 contract.
 */
static iec61850_data_object_t *ln_cdc_create_do(iec61850_cdc_t cdc,
                                                 const char *name)
{
    iec61850_data_object_t *dobj;

    switch (cdc) {
        /* Status CDCs */
        case IEC61850_CDC_SPS: dobj = iec61850_cdc_create_sps(name); break;
        case IEC61850_CDC_DPS: dobj = iec61850_cdc_create_dps(name); break;
        case IEC61850_CDC_INS: dobj = iec61850_cdc_create_ins(name); break;
        case IEC61850_CDC_ENS: dobj = iec61850_cdc_create_ens(name); break;
        case IEC61850_CDC_ACT: dobj = iec61850_cdc_create_act(name); break;
        case IEC61850_CDC_ACD: dobj = iec61850_cdc_create_acd(name); break;
        case IEC61850_CDC_SEC: dobj = iec61850_cdc_create_sec(name); break;
        /* Control CDCs */
        case IEC61850_CDC_SPC: dobj = iec61850_cdc_create_spc(name); break;
        case IEC61850_CDC_DPC: dobj = iec61850_cdc_create_dpc(name); break;
        case IEC61850_CDC_INC: dobj = iec61850_cdc_create_inc(name); break;
        case IEC61850_CDC_BSC: dobj = iec61850_cdc_create_bsc(name); break;
        /* Measurement CDCs */
        case IEC61850_CDC_MV:   dobj = iec61850_cdc_create_mv(name);   break;
        case IEC61850_CDC_CMV:  dobj = iec61850_cdc_create_cmv(name);  break;
        case IEC61850_CDC_SAV:  dobj = iec61850_cdc_create_sav(name);  break;
        case IEC61850_CDC_WYE:  dobj = iec61850_cdc_create_wye(name);  break;
        case IEC61850_CDC_DEL:  dobj = iec61850_cdc_create_del(name);  break;
        case IEC61850_CDC_MX3:  dobj = iec61850_cdc_create_mx3(name);  break;
        case IEC61850_CDC_DEL3: dobj = iec61850_cdc_create_del3(name); break;
        /* Setting CDCs */
        case IEC61850_CDC_SPG: dobj = iec61850_cdc_create_spg(name); break;
        case IEC61850_CDC_ASG: dobj = iec61850_cdc_create_asg(name); break;
        /* General CDCs */
        case IEC61850_CDC_LPL: dobj = iec61850_cdc_create_lpl(name); break;
        case IEC61850_CDC_DPL: dobj = iec61850_cdc_create_dpl(name); break;
        case IEC61850_CDC_BCR: dobj = iec61850_cdc_create_bcr(name); break;
        case IEC61850_CDC_VSS: dobj = iec61850_cdc_create_vss(name); break;
        /* WP-S6 stubs and unknown values: no factory -> fail */
        default:
            dobj = NULL;
            break;
    }

    return dobj;
}

/* ========================================================================
 * Model instantiation
 * ======================================================================== */

/*
 * Build the full LN name (prefix + lnClass + inst, e.g. "QXCBR1")
 * into out. Returns 0, or -ENAMETOOLONG on truncation.
 */
static int ln_build_full_name(char *out, size_t out_size,
                               const char *prefix, const char *ln_class,
                               const char *ln_inst)
{
    int ret = snprintf(out, out_size, "%s%s%s",
                       (prefix != NULL) ? prefix : "",
                       ln_class,
                       (ln_inst != NULL) ? ln_inst : "");

    if ((ret < 0) || ((size_t)ret >= out_size)) {
        return -ENAMETOOLONG;
    }
    return 0;
}

/*
 * Instantiate every MANDATORY DO of def into ln via the CDC factory
 * dispatch. Returns 0, or -ENOMEM when a factory or the LN DO array
 * is exhausted (the LN is destroyed by the caller).
 */
static int ln_instantiate_mandatory_dos(iec61850_logical_node_t *ln,
                                         const iec61850_ln_class_def_t *def)
{
    for (uint32_t i = 0U; i < def->do_count; i++) {
        const iec61850_ln_do_def_t *do_def = &def->dos[i];

        if (!do_def->mandatory) {
            continue; /* optional DOs are added on demand */
        }

        iec61850_data_object_t *dobj =
            ln_cdc_create_do(do_def->cdc, do_def->do_name);
        if (dobj == NULL) {
            return -ENOMEM;
        }
        if (iec61850_ln_add_data_object(ln, dobj) != 0) {
            iec61850_do_destroy(dobj);
            return -ENOMEM;
        }
    }
    return 0;
}

iec61850_logical_node_t *iec61850_ied_model_add_ln_class(
    iec61850_ied_model_t *model, const char *ld_name,
    const char *ln_class, const char *ln_inst, const char *prefix)
{
    const iec61850_ln_class_def_t *def;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *ln;
    char ln_name[IEC61850_MAX_NAME_LEN];

    if ((model == NULL) || (ld_name == NULL) || (ln_class == NULL)) {
        return NULL;
    }

    def = iec61850_ln_class_lookup(ln_class);
    if (def == NULL) {
        return NULL; /* unknown class */
    }

    /* Per the frozen contract the LD must already exist. */
    ld = iec61850_ied_model_find_ld(model, ld_name);
    if (ld == NULL) {
        return NULL; /* unknown LD */
    }

    /* Full LN name = prefix + lnClass + inst, stored in ln->ln_inst
     * (the scl_ied_builder.c convention — required by
     * iec61850_ied_model_register_mms(), which uses ln_inst as the
     * MMS LN name, e.g. "XCBR1$ST$Pos$stVal"). */
    if (ln_build_full_name(ln_name, sizeof(ln_name), prefix,
                            def->ln_class, ln_inst) != 0) {
        return NULL;
    }

    ln = iec61850_ln_create(def->ln_class, ln_name);
    if (ln == NULL) {
        return NULL;
    }

    if (ln_instantiate_mandatory_dos(ln, def) != 0) {
        iec61850_ln_destroy(ln);
        return NULL; /* factory failure (unimplemented CDC) */
    }

    if (iec61850_ld_add_logical_node(ld, ln) != 0) {
        iec61850_ln_destroy(ln);
        return NULL; /* LD full */
    }

    return ln;
}

/* ========================================================================
 * Optional-DO addition
 * ======================================================================== */

int iec61850_ln_add_ln_class_do(iec61850_logical_node_t *ln,
                                  const char *ln_class,
                                  const char *do_name)
{
    const iec61850_ln_class_def_t *def;
    const iec61850_ln_do_def_t *do_def = NULL;
    iec61850_data_object_t *dobj;

    if ((ln == NULL) || (ln_class == NULL) || (do_name == NULL)) {
        return -ENOENT;
    }

    def = iec61850_ln_class_lookup(ln_class);
    if (def == NULL) {
        return -ENOENT; /* unknown class */
    }

    /* The class definition must belong to this LN. */
    if (strcmp(ln->ln_class, def->ln_class) != 0) {
        return -ENOENT;
    }

    for (uint32_t i = 0U; i < def->do_count; i++) {
        if (strcmp(def->dos[i].do_name, do_name) == 0) {
            do_def = &def->dos[i];
            break;
        }
    }
    if (do_def == NULL) {
        return -ENOENT; /* unknown DO name for this class */
    }

    if (iec61850_ln_find_do(ln, do_name) != NULL) {
        return -EEXIST; /* already present (M or previously added) */
    }

    dobj = ln_cdc_create_do(do_def->cdc, do_def->do_name);
    if (dobj == NULL) {
        return -ENOMEM; /* CDC not implemented */
    }
    if (iec61850_ln_add_data_object(ln, dobj) != 0) {
        iec61850_do_destroy(dobj);
        return -ENOMEM; /* LN DO array full */
    }

    return 0;
}
